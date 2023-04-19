use std::{thread};
use std::net::{Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration};

use itertools::Itertools;
use nix::sys::signal::{kill, SIGHUP};
use nix::unistd::Pid;
use pnet::datalink;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::ipnetwork::{IpNetwork, Ipv6Network};
use regex::Regex;
use sysinfo::{PidExt, ProcessExt, SystemExt};
use tracing::{debug, error, warn};
use tracing::field::debug;

use crate::config::{ProgramConfig, SendInterface};
use crate::ras::{ICMPV6_ROUTER_ADVERTISEMENT, Ipv6Packet, PREFIX_OPTION_TYPE, PrefixInformation, RouterAdvertisement, to_packet};

/// get and interface channel by name of interface to send and receive
pub fn get_interface_channel(interface_name: &str) -> Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    // find the interface by name
    let Some(interface) = get_interface(interface_name) else {
        return None;
    };

    // create a channel to receive packets on the interface
    let channel_result = match datalink::channel(&interface, Config::default()) {
        Ok(channel) => channel,
        Err(e) => {
            error!("Failed to create datalink channel: {}", e);
            return None;
        }
    };
    let Ethernet(tx, rx) = channel_result else {
            error!("Could not create channel; it is not of type ethernet");
            return None;
    };
    Some((tx, rx))
}

/// get an interface by name
pub fn get_interface(interface_name: &str) -> Option<NetworkInterface> {
    // find the interface by name
    let interface = datalink::interfaces().into_iter().find(|iface| &iface.name == interface_name);
    if interface.is_none() {
        error!("Interface {} not found", interface_name);
    }
    interface
}

/// send reload signal to dhcpv6 process, which is searched by applying all strings `ProgramConfig.dhcpv6_process_filter` as filter to all processes
fn reload_dhcpcd(filter: Vec<String>) {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    if let Some((pid, process)) = system.processes().iter().find(|(_, p)| {
        let cmd = p.cmd().join(" ");
        filter.iter().all(|w| cmd.contains(w))
    }) {
        debug!("Sending signal to process with pid: {}, cmd: {}", pid, process.cmd().join(" "));
        if let Err(err) = kill(Pid::from_raw(pid.as_u32() as i32), SIGHUP) {
            error!("Signaling process {pid} failed: {err}");
        }
    } else {
        warn!("No process for filter '{}' found", filter.join(", "));
    }
}

/// listen to all RAs on given channel and send RAs, if needed
pub fn listen_to_ras(mut rx: Box<dyn DataLinkReceiver>, config: &ProgramConfig) {
    // receive and process packets
    let storage: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(vec![]));
    // mac to match packets against
    let upstream_mac = MacAddr::from_str(&config.upstream_mac).unwrap().octets();
    loop {
        match rx.next() {
            Ok(packet) => {
                // check if packet is RA and matches mac
                if packet.len() <= 56 || packet[54] != 134 || packet[55] != 0 || packet[6..12] != upstream_mac {
                    continue;
                }
                // get packet
                let Some(packet) = Ipv6Packet::from_bytes(packet) else {
                    continue;
                };
                // check checksum
                if packet.icmpv6_checksum() != packet.ra.checksum {
                    warn!("Wrong checksum for {:x?}", packet);
                    continue;
                }

                // give packet to thread to handle
                let config_clone = config.clone();
                let storage_clone = storage.clone();
                debug!("Got packet {:x?}", packet);
                thread::spawn(|| {
                    work_received_ra(packet, config_clone, storage_clone);
                });
            }
            Err(e) => warn!("Failed to receive packet: {}", e),
        }
    }
}

/// take received RA and check if RAs need to be sent
fn work_received_ra(packet: Ipv6Packet, config: ProgramConfig, storage: Arc<RwLock<Vec<String>>>) {
    let mut lock = storage.write().unwrap();
    let mut found = false;
    // check if any previously received prefix is missing in this RA
    for prefix in lock.clone() {
        if !packet.ra.prefixes.iter().map(|p| p.prefix.to_string()).contains(&prefix) {
            found = true;
        }
    }
    // clear previously received prefixes and add prefixes of this RA
    lock.clear();
    lock.append(
        &mut packet.ra.prefixes.iter()
            .filter(|p| config.prefixes_regex.is_match(&p.prefix.ip().to_string()))
            .map(|p| p.prefix.to_string()).collect()
    );
    // if needed, send RAs, from new threads
    if found {
        for send_interface in config.send_interfaces.clone() {
            let packet_clone = packet.clone();
            thread::spawn(|| {
                work_ra_for_interface(packet_clone, send_interface);
            });
        }
    }
    // wait one second to give threads time to get data
    thread::sleep(Duration::from_secs(1));
    // reload dhcpv6, os it pulls new prefix from upstream router
    reload_dhcpcd(config.dhcpv6_process_filter);
}

/// send RA on given interface, if this interface has any ipv6 address matching the regex for this interface
fn work_ra_for_interface(packet: Ipv6Packet, interface_param: SendInterface) {
    // get interface
    let Some(interface) = get_interface(&interface_param.name) else {
        return;
    };
    // get mac of this interface
    let Some(mac) = interface.mac else {
        warn!("Interface {} does not have a mac, skipping!", interface_param.name);
        return;
    };
    // get link-local address of this interface
    let link_local_regex = Regex::from_str("^fe80:.*").unwrap();
    let IpNetwork::V6(source_net) = interface.ips.iter().find(|ip| link_local_regex.is_match(&ip.ip().to_string())).unwrap() else {
        warn!("No fe80 on interface {}, skipping!", interface_param.name);
        return;
    };
    // construct router advertisement
    let mut ra = RouterAdvertisement {
        hop_limit: packet.ra.hop_limit,
        code: PREFIX_OPTION_TYPE,
        icmp_type: ICMPV6_ROUTER_ADVERTISEMENT,
        checksum: 0,
        flags: packet.ra.flags,
        router_lifetime: 0,
        reachable_time: 0,
        retrans_timer: 0,
        prefixes: vec![],
    };
    // search for ips
    for ip in &interface.ips {
        // if interface is not v6, skip it
        let IpNetwork::V6(address) = ip else {
            continue;
        };
        // check if this ip matches any given regex
        for prefix in &interface_param.prefixes {
            if prefix.regex.is_match(&ip.ip().to_string()) {
                // get as [u8] and remove host bits
                let mut octets = address.ip().octets();
                apply_netmask(&mut octets, prefix.length as usize);
                // add prefix to RA
                ra.prefixes.push(PrefixInformation {
                    flags: 192,
                    valid_lifetime: 0,
                    preferred_lifetime: 0,
                    prefix: Ipv6Network::new(Ipv6Addr::from(octets), prefix.length).unwrap(),
                });
                break;
            }
        }
    }
    // construct packet
    let mut ipv6_packet = Ipv6Packet {
        source_mac: mac,
        source_ip: source_net.ip(),
        dest_ip: Ipv6Addr::from_str("ff02::1").unwrap(),
        ra,
    };
    // get channel to send
    let Some((mut tx, _)) = get_interface_channel(&interface_param.name) else {
        return;
    };
    // convert packet to binary data
    let vec = to_packet(&mut ipv6_packet);
    // send packet
    tx.send_to(&vec, None);
    // send packet again, for each delay setting, and wait between sends
    for delay in interface_param.send_delays {
        thread::sleep(Duration::from_secs(delay as u64));
        tx.send_to(&vec, None);
    }
}

/// this will remove all set host bits in the given ipv6 address
pub fn apply_netmask(ipv6: &mut [u8; 16], mask_len: usize) {
    let mut net_bytes = [0u8; 16];
    for i in 0..mask_len / 8 {
        net_bytes[i] = 255;
    }

    if mask_len % 8 != 0 {
        let bit_offset = mask_len % 8;
        let mask_byte = 255u8 << (8 - bit_offset);
        net_bytes[mask_len / 8] = mask_byte;
    }

    for i in 0..16 {
        ipv6[i] &= net_bytes[i];
    }
}
