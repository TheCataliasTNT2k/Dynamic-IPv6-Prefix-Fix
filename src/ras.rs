use std::convert::TryInto;
use std::net::Ipv6Addr;

use pnet::datalink::MacAddr;
use pnet::ipnetwork::Ipv6Network;
use tracing::warn;

pub(crate) const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub(crate) const PREFIX_OPTION_TYPE: u8 = 3;

#[derive(Debug, Clone)]
pub(crate) struct Ipv6Packet {
    pub(crate) source_mac: MacAddr,
    pub(crate) source_ip: Ipv6Addr,
    pub(crate) dest_ip: Ipv6Addr,
    pub(crate) ra: RouterAdvertisement,
    pub(crate) payload: Vec<u8>,
}

impl Ipv6Packet {
    /// read ipv6 packet from byte array
    pub(crate) fn from_bytes(bytes: &[u8], mac: MacAddr) -> Option<Self> {
        // store stuff of this packet into vars
        let source: [u8; 16] = <[u8; 16]>::try_from(&bytes[10..26]).unwrap();
        let dest: [u8; 16] = <[u8; 16]>::try_from(&bytes[26..42]).unwrap();

        // remove ipv6 data from packet
        let ra_data = &bytes[42..];
        if ra_data.len() < 16 || ra_data[1] != 0 {
            warn!("Not an RA: {:x?}", bytes);
            return None;
        }

        // parse the packet as an RA packet
        let ra = RouterAdvertisement::from_bytes(ra_data);
        let ipv6_packet = Ipv6Packet {
            source_mac: mac,
            source_ip: Ipv6Addr::from(source),
            dest_ip: Ipv6Addr::from(dest),
            ra,
            payload: ra_data.to_vec(),
        };
        Some(ipv6_packet)
    }

    /// calculates the checksum of the ipv6 packet\
    /// the RA data of this packet is used as payload
    pub(crate) fn imcpv6_checksum(&self) -> u16 {
        return Ipv6Packet::icmpv6_checksum_raw(self, self.ra.to_vec(self));
    }

    // thanks chatgpt
    /// calculates the checksum of the ipv6 packet, with given payload\
    /// useful if your payload is not the same as the RA sotred in this packet
    pub(crate) fn icmpv6_checksum_raw(&self, mut icmp_payload: Vec<u8>) -> u16 {
        let mut sum = 0;
        let _ = std::mem::replace(&mut icmp_payload[2], 0);
        let _ = std::mem::replace(&mut icmp_payload[3], 0);

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
        sum += u32::from(icmp_payload.len() as u16);

        // Add upper layer packet
        for i in (0..icmp_payload.len()).step_by(2) {
            if i == icmp_payload.len() - 1 {
                sum += u32::from(icmp_payload[i]) << 8;
            } else {
                let word = u16::from_be_bytes([icmp_payload[i], icmp_payload[i + 1]]);
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
        self.ra.checksum = self.imcpv6_checksum();
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

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EthernetPacket {
    pub(crate) dest: MacAddr,
    pub(crate) src: MacAddr,
    pub(crate) vlan_tag: Option<u16>,
    pub(crate) payload: Vec<u8>,
}

impl EthernetPacket {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 14 {
            warn!("Not a valid packet: {:x?}", bytes);
            return None;
        }
        let mut offset = 0;
        let dest = [
            bytes[offset], bytes[offset + 1], bytes[offset + 2],
            bytes[offset + 3], bytes[offset + 4], bytes[offset + 5],
        ];
        offset += 6;
        let src = [
            bytes[offset], bytes[offset + 1], bytes[offset + 2],
            bytes[offset + 3], bytes[offset + 4], bytes[offset + 5],
        ];
        offset += 6;
        let (vlan_tag, payload_offset) = if bytes[offset..].starts_with(&[0x81, 0x00]) {
            if bytes.len() < 18 {
                return None;
            }
            let vlan_tag = ((bytes[offset + 2] as u16) << 8) | (bytes[offset + 3] as u16);
            (Some(vlan_tag), offset + 4)
        } else {
            (None, offset)
        };
        let payload = bytes[payload_offset..].to_vec();
        Some(Self {
            dest: MacAddr::new(dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]),
            src: MacAddr::new(src[0], src[1], src[2], src[3], src[4], src[5]),
            vlan_tag,
            payload,
        })
    }
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
