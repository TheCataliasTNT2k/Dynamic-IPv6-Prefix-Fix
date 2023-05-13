use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::Thread;
use std::time::{Duration, Instant};
use std::{mem, thread};

use itertools::Itertools;
use nix::sys::signal::{kill, SIGHUP};
use nix::unistd::Pid;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv6Network};
use regex::Regex;
use sysinfo::{PidExt, ProcessExt, SystemExt};
use tracing::{debug, error, info, warn};

use crate::config::{ProgramConfig, SendInterface};
use crate::packets::{
    EthernetPacket, Ipv6Packet, PrefixInformation, RouterAdvertisement,
    ICMPV6_ROUTER_ADVERTISEMENT, PREFIX_OPTION_TYPE,
};

type PrefixStorage = Arc<Mutex<(Vec<String>, HashMap<String, Instant>)>>;
type ThreadMap = Arc<Mutex<(Thread, HashMap<Ipv6Addr, HashSet<u8>>)>>;
type InterfaceMutex = Mutex<HashMap<String, ThreadMap>>;

struct Sync {
    map: InterfaceMutex,
    counter: AtomicIsize,
    prefix_storage: PrefixStorage,
    found: AtomicBool,
    parent_thread: RwLock<Thread>,
    parent_sleep_timer: Mutex<Instant>,
}

/// get and interface channel by name of interface to send and receive
pub(crate) fn get_interface_channel(
    interface_name: &str,
) -> Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
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
pub(crate) fn get_interface(interface_name: &str) -> Option<NetworkInterface> {
    // find the interface by name
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name);
    if interface.is_none() {
        error!("Interface {} not found", interface_name);
    }
    interface
}

/// send reload signal to dhcpv6 process, which is searched by applying all strings `ProgramConfig.dhcpv6_process_filter` as filter to all processes
fn reload_dhcpcd(filter: &[String]) {
    let mut system = sysinfo::System::new();
    system.refresh_all();

    // find process
    if let Some((pid, process)) = system.processes().iter().find(|(_, p)| {
        let cmd = p.cmd().join(" ");
        filter.iter().all(|w| cmd.contains(w))
    }) {
        // send SIGHUP signal
        info!(
            "Sending signal to process with pid: {}, name: {}",
            pid,
            process.name()
        );
        if let Err(err) = kill(Pid::from_raw(pid.as_u32() as i32), SIGHUP) {
            error!("Signaling process {pid} failed: {err}");
        }
    } else {
        warn!("No process for filter '{}' found", filter.join(", "));
    }
}

/// listen to all RAs on given channel and send RAs, if needed
pub(crate) fn listen_to_ras(mut rx: Box<dyn DataLinkReceiver>, config: Arc<ProgramConfig>) {
    // save received prefixes to debounce
    let storage = Arc::new(Sync {
        map: Mutex::new(HashMap::new()),
        counter: AtomicIsize::new(0),
        prefix_storage: Arc::new(Mutex::new((vec![], HashMap::new()))),
        found: AtomicBool::new(false),
        parent_thread: RwLock::new(thread::current()),
        parent_sleep_timer: Mutex::new(Instant::now()),
    });
    // mac to match packets against
    let upstream_mac = MacAddr::from_str(&config.upstream_mac).unwrap().octets();
    let dest_mac = MacAddr::new(51, 51, 0, 0, 0, 1).octets();
    loop {
        match rx.next() {
            Ok(packet) => {
                handle_packet(
                    packet,
                    Arc::clone(&config),
                    Arc::clone(&storage),
                    (upstream_mac, dest_mac),
                );
            }
            Err(e) => warn!("Failed to receive packet: {}", e),
        }
    }
}

fn handle_packet(
    packet: &[u8],
    config: Arc<ProgramConfig>,
    storage: Arc<Sync>,
    macs: ([u8; 6], [u8; 6]),
) {
    // parse packet as ethernet
    let Some(ethernet_packet) = EthernetPacket::from_bytes(packet) else {
        return;
    };
    // check if packet is RA and matches mac (and a lot more)
    if ethernet_packet.payload.len() < 44
        || ethernet_packet.payload[42] != 134
        || ethernet_packet.payload[43] != 0
        || ethernet_packet.src != macs.0
        || ethernet_packet.dest != macs.1
    {
        return;
    }
    debug!("GOT RA: {:x?}", ethernet_packet);
    // get packet
    let Some(parsed_packet) = Ipv6Packet::from_bytes(&ethernet_packet.payload, ethernet_packet.src) else {
        return;
    };
    // check checksum
    let cs = parsed_packet.icmpv6_checksum_raw(parsed_packet.payload.clone());
    if cs != parsed_packet.ra.checksum {
        warn!(
            "Wrong checksum {}/{} for {:x?}",
            cs, parsed_packet.ra.checksum, packet
        );
        return;
    }

    // give packet to thread to handle
    let config_clone = Arc::clone(&config);
    thread::spawn(|| {
        work_received_ra(parsed_packet, config_clone, storage);
    });
}

/// take received RA and check if RAs need to be sent
fn work_received_ra(packet: Ipv6Packet, config: Arc<ProgramConfig>, storage: Arc<Sync>) {
    info!("{:?} Got RA", thread::current().id());
    while storage.counter.load(Ordering::Acquire) == -1 {
        debug!("{:?} Waiting, lock is held (-1)", thread::current().id());
        thread::sleep(Duration::from_secs(1));
    }
    let is_running = storage
        .counter
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err();
    if !is_running {
        let _ = mem::replace(
            &mut *storage.parent_thread.write().unwrap(),
            thread::current(),
        );
    } else {
        // we are here! wait for us!
        storage.counter.fetch_add(1, Ordering::SeqCst);
    }
    *storage.parent_sleep_timer.lock().unwrap() = Instant::now();

    let mut prefix_lock = storage.prefix_storage.lock().unwrap();
    let mut found = false;
    debug!(
        "{:?} GOT PREFIXES {:?}",
        thread::current().id(),
        packet.ra.prefixes
    );
    debug!(
        "{:?} NORMAL LOCK BEFORE: '{}', REMOVE LOCK BEFORE: '{}'",
        thread::current().id(),
        prefix_lock.0.join(" "),
        prefix_lock.1.keys().join(" ")
    );

    // check if any previously received prefix is missing in this RA; ignore all prefixes with lifetime 0
    for prefix in prefix_lock.0.clone() {
        if !packet
            .ra
            .prefixes
            .iter()
            .filter(|p| p.preferred_lifetime > 0)
            .map(|p| p.prefix.to_string())
            .contains(&prefix)
        {
            debug!(
                "{:?} FOUND missing: {}",
                thread::current().id(),
                prefix.to_string()
            );
            found = true;
        }
    }
    // check for new prefixes (not received in the last RA)
    for prefix in &packet.ra.prefixes {
        // do not use lifetime 0 prefixes here
        if prefix.preferred_lifetime > 0 {
            if !prefix_lock.0.iter().contains(&prefix.prefix.to_string())
                && config
                    .prefixes_regex
                    .is_match(&prefix.prefix.ip().to_string())
                && !config.ignore_new_prefixes
            {
                debug!(
                    "{:?} FOUND new: {}",
                    thread::current().id(),
                    prefix.prefix.to_string()
                );
                found = true;
            }
            // else if we got same prefix with lifetime 0 earlier, remove it from second storage
            prefix_lock.1.remove(&prefix.prefix.ip().to_string());
        } else if config
            .prefixes_regex
            .is_match(&prefix.prefix.ip().to_string())
        {
            // check if lifetime 0 prefixes were received within last 30 minutes; used for debounce
            match prefix_lock.1.get(&prefix.prefix.to_string()) {
                None => {
                    debug!(
                        "Got prefix with preferred-lifetime of 0: {}",
                        prefix.prefix.to_string()
                    );
                    found = true;
                }
                Some(value) => {
                    if value.elapsed().as_secs() >= 1800 {
                        found = true;
                    } else {
                        debug!("Got prefix with preferred-lifetime of 0: {}; ignoring it, because we got same RA within last 30 minutes", prefix.prefix.to_string());
                    }
                }
            }
            // reset decay timer for this lifetime 0 prefix
            prefix_lock
                .1
                .insert(prefix.prefix.to_string().clone(), Instant::now());
        }
    }
    // remove all lifetime 0 prefixes, which were not announces for 2 hours
    prefix_lock.1.retain(|_, v| v.elapsed().as_secs() <= 7260);
    // clear previously received prefixes and add prefixes of this RA; no lifetime 0 prefixes
    prefix_lock.0.clear();
    prefix_lock.0.append(
        &mut packet
            .ra
            .prefixes
            .iter()
            .filter(|p| p.preferred_lifetime > 0)
            .filter(|p| config.prefixes_regex.is_match(&p.prefix.ip().to_string()))
            .map(|p| p.prefix.to_string())
            .collect(),
    );
    debug!(
        "{:?} NORMAL LOCK AFTER: '{}', REMOVE LOCK AFTER: '{}'",
        thread::current().id(),
        prefix_lock.0.join(" "),
        prefix_lock.1.keys().join(" ")
    );
    drop(prefix_lock);
    if found {
        storage.found.store(true, Ordering::SeqCst);
    }

    // if needed, send RAs, from new threads
    let mut map_lock = storage.map.lock().unwrap();
    for send_interface in config.send_interfaces.clone() {
        let packet_clone = packet.clone();
        let storage_clone = Arc::clone(&storage);
        let config_clone = Arc::clone(&config);
        let mutex = map_lock
            .entry(send_interface.name.clone())
            .or_insert_with(|| Arc::new(Mutex::new((thread::current(), HashMap::new()))))
            .clone();
        storage.counter.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            debug!("{:?} Starting thread", thread::current().id());
            work_ra_for_interface(
                packet_clone,
                send_interface,
                storage_clone,
                mutex,
                is_running,
                config_clone,
            );
        });
    }
    drop(map_lock);

    if is_running {
        // if only parent remains
        if storage.counter.fetch_sub(1, Ordering::SeqCst) == 2 {
            // unpark parent
            storage.parent_thread.read().unwrap().unpark();
        }
        return;
    }

    // wait until all threads finished ip filtering
    debug!("{:?} Waiting before reload", thread::current().id());
    loop {
        while storage
            .counter
            .compare_exchange(1, -1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!("{:?} Parent parking!", thread::current().id());
            thread::park_timeout(Duration::from_secs(60));
            thread::sleep(Duration::from_secs(1));
        }
        if storage
            .parent_sleep_timer
            .lock()
            .unwrap()
            .elapsed()
            .as_secs()
            >= config.wait_before_dhcpv6_reload as u64
        {
            break;
        }
        storage.counter.store(1, Ordering::SeqCst);
        debug!("{:?} Parent waiting!", thread::current().id());
        thread::sleep(Duration::from_secs(1));
    }
    debug!("{:?} Parent resuming!", thread::current().id());

    if storage.found.load(Ordering::Acquire) {
        info!("{:?} Reload!", thread::current().id());
        reload_dhcpcd(&config.dhcpv6_process_filter);
    } else {
        info!("{:?} No reload needed!", thread::current().id());
    }

    let mut new_map_lock = storage.map.lock().unwrap();
    debug!("{:?} Unparking workers!", thread::current().id());
    for mutex in new_map_lock.values() {
        mutex.lock().unwrap().0.unpark();
    }

    // tidy up everything
    new_map_lock.clear();
    storage.found.store(false, Ordering::SeqCst);
    storage.counter.store(0, Ordering::SeqCst);
}

/// send RA on given interface, if this interface has any ipv6 address matching the regex for this interface
fn work_ra_for_interface(
    packet: Ipv6Packet,
    interface_param: SendInterface,
    storage: Arc<Sync>,
    mutex: ThreadMap,
    early_return: bool,
    config: Arc<ProgramConfig>,
) {
    let mut lock = mutex.lock().unwrap();
    // get interface
    let Some(interface) = get_interface(&interface_param.name) else {
        return;
    };
    debug!(
        "{:?} IPs on interface '{}': {}",
        thread::current().id(),
        interface_param.name,
        interface.ips.iter().map(ToString::to_string).join(" ")
    );
    for ip in &interface.ips {
        // if interface is not v6, skip it
        let IpNetwork::V6(address) = ip else {
            continue;
        };
        // check if this ip matches any given regex
        for prefix in &interface_param.prefixes {
            if prefix.regex.is_match(&ip.ip().to_string()) {
                lock.1
                    .entry(address.ip())
                    .or_insert(HashSet::new())
                    .insert(prefix.length);
                break;
            }
            debug!(
                "{:?} IF {}: {} does not match {}",
                thread::current().id(),
                interface_param.name,
                ip.ip().to_string(),
                prefix.regex.to_string()
            );
        }
    }
    debug!(
        "{:?} Stored IPs for interface: {}",
        thread::current().id(),
        lock.1
            .iter()
            .map(|(ip, l)| format!("{}: {}", ip, l.iter().join(", ")))
            .join("; ")
    );
    // release "thread is working" lock
    // if only parent remains
    debug!(
        "{:?} Remaining threads before subtraction: {}",
        thread::current().id(),
        storage.counter.load(Ordering::Acquire)
    );
    if storage.counter.fetch_sub(1, Ordering::SeqCst) <= 2 {
        // unpark parent
        debug!("{:?} Unparking parent", thread::current().id());
        storage.parent_thread.read().unwrap().unpark();
    }
    if early_return {
        // release lock for this thread's data
        drop(lock);
        return;
    }
    let _ = mem::replace(&mut lock.0, thread::current());
    // release lock for this thread's data
    drop(lock);
    drop(interface);

    // wait until dhcp reloaded
    thread::park_timeout(Duration::from_secs(60));
    debug!("{:?} Worker waiting for ip!", thread::current().id());
    thread::sleep(Duration::from_secs(config.wait_after_dhcpv6_reload as u64));
    debug!("{:?} Worker resuming!", thread::current().id());
    // need new lock for this thread's data now
    let mut new_lock = mutex.lock().unwrap();

    // get interface
    let Some(new_interface) = get_interface(&interface_param.name) else {
        return;
    };
    // get mac of this interface
    let Some(mac) = new_interface.mac else {
        warn!("Interface {} does not have a mac, skipping!", interface_param.name);
        return;
    };
    // get link-local address of this interface
    let link_local_regex = Regex::from_str("^fe80:.*").unwrap();
    let IpNetwork::V6(source_net) = new_interface.ips.iter().find(|ip| link_local_regex.is_match(&ip.ip().to_string())).unwrap() else {
        warn!("No fe80 on interface {}, skipping!", interface_param.name);
        return;
    };
    debug!("{:?} Got link local", thread::current().id());
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
    debug!(
        "{:?} IPs on interface '{}': {}",
        thread::current().id(),
        interface_param.name,
        new_interface.ips.iter().map(ToString::to_string).join(" ")
    );
    // search for ips
    for ip in &new_interface.ips {
        // if interface is not v6, skip it
        let IpNetwork::V6(address) = ip else {
            continue;
        };
        new_lock.1.remove(&address.ip());
    }
    debug!(
        "{:?} Stored IPs for interface: {}",
        thread::current().id(),
        new_lock
            .1
            .iter()
            .map(|(ip, l)| format!("{}: {}", ip, l.iter().join(", ")))
            .join("; ")
    );
    new_lock.1.iter().for_each(|(ip, lengths)| {
        for length in lengths {
            // get as [u8] and remove host bits
            let mut octets = ip.octets();
            apply_netmask(&mut octets, *length as usize);
            // add prefix to RA
            ra.prefixes.push(PrefixInformation {
                flags: 192,
                valid_lifetime: 0,
                preferred_lifetime: 0,
                prefix: Ipv6Network::new(Ipv6Addr::from(octets), *length).unwrap(),
            });
        }
    });
    drop(new_lock);
    debug!(
        "{:?} Found ips: {}",
        thread::current().id(),
        ra.prefixes.iter().map(|p| p.prefix.to_string()).join(" ")
    );
    // construct packet
    let mut ipv6_packet = Ipv6Packet {
        source_mac: mac,
        source_ip: source_net.ip(),
        dest_ip: Ipv6Addr::from_str("ff02::1").unwrap(),
        ra,
        payload: vec![],
    };
    if ipv6_packet.ra.prefixes.is_empty() {
        info!(
            "{:?} Nothing to send on interface {}",
            thread::current().id(),
            interface_param.name
        );
        return;
    }
    // get channel to send
    let Some((mut tx, _)) = get_interface_channel(&interface_param.name) else {
        return;
    };
    info!(
        "{:?} Sending RAs for '{}' on interface {}",
        thread::current().id(),
        ipv6_packet
            .ra
            .prefixes
            .iter()
            .map(|p| p.prefix.to_string())
            .join(", "),
        interface_param.name
    );
    // convert packet to binary data
    let vec = ipv6_packet.as_packet();
    // send packet
    tx.send_to(&vec, None);
    // send packet again, for each delay setting, and wait between sends
    for delay in interface_param.send_delays {
        thread::sleep(Duration::from_secs(u64::from(delay)));
        tx.send_to(&vec, None);
    }
}

/// this will remove all set host bits in the given ipv6 address
pub(crate) fn apply_netmask(ipv6: &mut [u8; 16], mask_len: usize) {
    let mut net_bytes = [0u8; 16];
    for byte in net_bytes.iter_mut().take(mask_len / 8) {
        *byte = 255;
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
