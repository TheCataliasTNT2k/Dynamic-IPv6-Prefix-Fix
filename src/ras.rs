use std::convert::TryInto;
use std::net::Ipv6Addr;

use pnet::datalink::MacAddr;
use pnet::ipnetwork::Ipv6Network;
use tracing::warn;

pub(crate) const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub(crate) const PREFIX_OPTION_TYPE: u8 = 3;

#[derive(Debug, Clone)]
pub struct Ipv6Packet {
    pub(crate) source_mac: MacAddr,
    pub(crate) source_ip: Ipv6Addr,
    pub(crate) dest_ip: Ipv6Addr,
    pub(crate) ra: RouterAdvertisement,
}

impl Ipv6Packet {
    /// read ipv6 packet from byte array
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // store stuff of this packet into vars
        let mac = &bytes[6..12];
        let source: [u8; 16] = <[u8; 16]>::try_from(&bytes[22..38]).unwrap();
        let dest: [u8; 16] = <[u8; 16]>::try_from(&bytes[38..54]).unwrap();

        // remove ipv6 data from packet
        let ra_data = &bytes[54..];
        if ra_data.len() < 16 || ra_data[1] != 0 {
            warn!("Not an RA: {:x?}", bytes);
            return None;
        }

        // parse the packet as an RA packet
        let ra = RouterAdvertisement::from_bytes(ra_data);
        let ipv6_packet = Ipv6Packet {
            source_mac: MacAddr::new(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            source_ip: Ipv6Addr::from(source),
            dest_ip: Ipv6Addr::from(dest),
            ra,
        };
        Some(ipv6_packet)
    }

    // thanks chatgpt
    pub(crate) fn icmpv6_checksum(&self) -> u16 {
        let mut sum = 0;
        let mut ra_clone = self.ra.clone();
        ra_clone.checksum = 0;
        let payload = ra_clone.to_vec(self);

        // Add source address
        for i in (0..16).step_by(2) {
            let word = u16::from_be_bytes([self.source_ip.octets()[i], self.source_ip.octets()[i + 1]]);
            sum += u32::from(word);
        }

        // Add destination address
        for i in (0..16).step_by(2) {
            let word = u16::from_be_bytes([self.dest_ip.octets()[i], self.dest_ip.octets()[i + 1]]);
            sum += u32::from(word);
        }

        // Add upper layer packet length and protocol
        sum += u32::from(58u16);
        sum += u32::from(payload.len() as u16);

        // Add upper layer packet
        for i in (0..payload.len()).step_by(2) {
            if i == payload.len() - 1 {
                sum += u32::from(payload[i]) << 8;
            } else {
                let word = u16::from_be_bytes([payload[i], payload[i + 1]]);
                sum += u32::from(word);
            }
        }

        // Fold carries
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take one's complement of sum
        !sum as u16
    }

    /// generate the icmpv6 checksum and store it
    pub(crate) fn generate_and_store_checksum(&mut self) {
        self.ra.checksum = 0;
        self.ra.checksum = self.icmpv6_checksum();
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct RouterAdvertisement {
    pub(crate) hop_limit: u8,
    pub(crate) code: u8,
    pub(crate) icmp_type: u8,
    pub(crate) checksum: u16,
    pub(crate) flags: u8,
    pub(crate) router_lifetime: u16,
    pub(crate) reachable_time: u32,
    pub(crate) retrans_timer: u32,
    pub(crate) prefixes: Vec<PrefixInformation>,
}

impl RouterAdvertisement {
    /// read router advertisement from byte array
    fn from_bytes(data: &[u8]) -> Self {
        // store interesting stuff in vars
        let msg_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let hop_limit = data[4];
        let flags = data[5];
        let router_lifetime = u16::from_be_bytes(data[6..8].try_into().unwrap());
        let reachable_time = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let retrans_timer = u32::from_be_bytes(data[12..16].try_into().unwrap());

        let mut pos = 16;
        let mut prefixes: Vec<PrefixInformation> = vec![];

        while pos < data.len() {
            let opt_type = data[pos];
            let opt_len = data[pos + 1] as usize * 8;

            if opt_type == PREFIX_OPTION_TYPE {
                let prefix_length = data[pos + 2];
                let option_flags = data[pos + 3];
                let valid_lifetime = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap());
                let preferred_lifetime =
                    u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
                let prefix = Ipv6Network::new(
                    Ipv6Addr::from(<[u8; 16]>::try_from(&data[pos + 16..pos + 32]).unwrap()),
                    prefix_length,
                ).unwrap();

                prefixes.push(PrefixInformation {
                    flags: option_flags,
                    valid_lifetime,
                    preferred_lifetime,
                    prefix,
                });
            }

            pos += opt_len;
        }

        RouterAdvertisement {
            hop_limit,
            code,
            icmp_type: msg_type,
            checksum,
            flags,
            router_lifetime,
            reachable_time,
            retrans_timer,
            prefixes,
        }
    }

    /// return the RA as vector
    pub(crate) fn to_vec(&self, ipv6_packet: &Ipv6Packet) -> Vec<u8> {
        let mut data = vec![ICMPV6_ROUTER_ADVERTISEMENT, 0];

        // Add checksum
        data.extend_from_slice(&self.checksum.to_be_bytes());

        // add hoplimit and flags
        data.extend_from_slice(&[self.hop_limit, self.flags]);

        // Add router lifetime
        data.extend_from_slice(&self.router_lifetime.to_be_bytes());

        // Add reachable time
        data.extend_from_slice(&self.reachable_time.to_be_bytes());

        // Add retransmission timer
        data.extend_from_slice(&self.retrans_timer.to_be_bytes());

        // Add prefixes
        for prefix in &self.prefixes {
            // Add prefix option type, prefix option length (in bytes), prefix length, flags
            data.extend_from_slice(&[PREFIX_OPTION_TYPE, 4, prefix.prefix.prefix(), prefix.flags]);

            // Add valid lifetime
            data.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());

            // Add preferred lifetime
            data.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());

            // Add reserved space
            data.extend_from_slice(&[0, 0, 0, 0]);

            // Add prefix
            data.extend_from_slice(&prefix.prefix.ip().octets());
        }

        // Add source link layer option and length
        data.extend_from_slice(&[1, 1]);
        // add source mac
        data.extend_from_slice(&ipv6_packet.source_mac.octets());

        data
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PrefixInformation {
    pub(crate) flags: u8,
    pub(crate) valid_lifetime: u32,
    pub(crate) preferred_lifetime: u32,
    pub(crate) prefix: Ipv6Network,
}

pub(crate) fn to_packet(payload: &mut Ipv6Packet) -> Vec<u8> {
    payload.generate_and_store_checksum();
    let data = payload.ra.to_vec(payload);

    // create storage; add destination mac
    let mut ip_buf = vec![51, 51, 0, 0, 0, 1];
    // add source mac
    ip_buf.extend_from_slice(&payload.source_mac.octets());
    ip_buf.extend_from_slice(&[
        // add rest of ethernet header (type)
        134, 221,
        // add ip version, traffic class, flow label
        // be aware, these are byte aligned here, (e.g. ip version is 4 bit in packet, so it was merged with next 4 bit)
        96, 4, 172, 239
    ]);
    // add payload length
    ip_buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    // add next header and hop limit
    ip_buf.extend_from_slice(&[58, 255]);
    // add source ip
    ip_buf.extend_from_slice(&payload.source_ip.octets());
    // add destination ip
    ip_buf.extend_from_slice(&payload.dest_ip.octets());
    // add icmp data
    ip_buf.extend_from_slice(&data);
    ip_buf
}
