//! The link, network and transport layers: from a captured frame to a UDP datagram, or
//! to a PTP message sent straight over Ethernet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::capture::{self, LinkType};

/// The EtherType of PTP carried directly over Ethernet (IEEE 1588-2008 Annex F).
pub const ETHERTYPE_PTP: u16 = 0x88F7;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// 802.1Q, 802.1ad and the pre-standard 9100h that some switches use for QinQ.
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88A8, 0x9100];

const PROTOCOL_UDP: u8 = 17;

/// What a frame carries, as far as the analyser is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    /// A UDP datagram, or the first fragment of one.
    Udp(Datagram<'a>),
    /// A later fragment of a fragmented IP packet, which has no UDP header.
    Fragment {
        /// The sender.
        source: IpAddr,
        /// The destination.
        destination: IpAddr,
    },
    /// A PTP message sent over Ethernet.
    Ptp {
        /// The sender's MAC address.
        source: [u8; 6],
        /// The message.
        payload: &'a [u8],
    },
    /// Anything else, or a frame too short to read.
    Other,
}

/// A UDP datagram as captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// The sender's address and port.
    pub source: SocketAddr,
    /// The destination address and port.
    pub destination: SocketAddr,
    /// The UDP length field: octets of header and payload.
    pub length: u16,
    /// The payload as captured: shorter than `length` less the 8-octet header when the
    /// capture cut the frame short or the IP packet was fragmented.
    pub payload: &'a [u8],
    /// Whether the IP packet was the first fragment of a larger one.
    pub fragmented: bool,
    /// Octets of the IP packet: the IP header and everything after it.
    pub ip_length: u32,
}

impl Datagram<'_> {
    /// Whether the whole payload was captured.
    pub fn complete(&self) -> bool {
        !self.fragmented && self.payload.len() + 8 == usize::from(self.length)
    }
}

/// Reads a captured frame down to UDP.
pub fn parse(link: LinkType, data: &[u8]) -> Packet<'_> {
    let (ethertype, rest, source) = match link {
        capture::ETHERNET => match ethernet(data) {
            Some(found) => found,
            None => return Packet::Other,
        },
        capture::LINUX_SLL => {
            let Some(header) = data.get(..16) else { return Packet::Other };
            let length = usize::from(u16::from_be_bytes([header[4], header[5]])).min(8);
            let mut source = [0; 6];
            if length == 6 {
                source.copy_from_slice(&header[6..12]);
            }
            let (ethertype, rest) = vlan(u16::from_be_bytes([header[14], header[15]]), &data[16..]);
            (ethertype, rest, source)
        }
        capture::LINUX_SLL2 => {
            let Some(header) = data.get(..20) else { return Packet::Other };
            let mut source = [0; 6];
            if header[11] == 6 {
                source.copy_from_slice(&header[12..18]);
            }
            let (ethertype, rest) = vlan(u16::from_be_bytes([header[0], header[1]]), &data[20..]);
            (ethertype, rest, source)
        }
        capture::RAW | capture::IPV4 | capture::IPV6 => match data.first().map(|b| b >> 4) {
            Some(4) => (ETHERTYPE_IPV4, data, [0; 6]),
            Some(6) => (ETHERTYPE_IPV6, data, [0; 6]),
            _ => return Packet::Other,
        },
        _ => return Packet::Other,
    };
    match ethertype {
        ETHERTYPE_IPV4 => ipv4(rest),
        ETHERTYPE_IPV6 => ipv6(rest),
        ETHERTYPE_PTP => Packet::Ptp { source, payload: rest },
        _ => Packet::Other,
    }
}

/// The EtherType after any VLAN tags, what follows it, and the source MAC address.
fn ethernet(data: &[u8]) -> Option<(u16, &[u8], [u8; 6])> {
    let header = data.get(..14)?;
    let mut source = [0; 6];
    source.copy_from_slice(&header[6..12]);
    let (ethertype, rest) = vlan(u16::from_be_bytes([header[12], header[13]]), &data[14..]);
    Some((ethertype, rest, source))
}

/// Skips VLAN tags: each is a tag control word and the next EtherType.
fn vlan(mut ethertype: u16, mut rest: &[u8]) -> (u16, &[u8]) {
    while ETHERTYPE_VLAN.contains(&ethertype) {
        let Some(tag) = rest.get(..4) else { return (0, &[]) };
        ethertype = u16::from_be_bytes([tag[2], tag[3]]);
        rest = &rest[4..];
    }
    (ethertype, rest)
}

fn ipv4(data: &[u8]) -> Packet<'_> {
    let Some(header) = data.get(..20) else { return Packet::Other };
    let header_length = usize::from(header[0] & 0x0F) * 4;
    if header[0] >> 4 != 4 || header_length < 20 {
        return Packet::Other;
    }
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let flags = u16::from_be_bytes([header[6], header[7]]);
    let more_fragments = flags & 0x2000 != 0;
    let offset = flags & 0x1FFF;
    let source = IpAddr::V4(Ipv4Addr::new(header[12], header[13], header[14], header[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(header[16], header[17], header[18], header[19]));
    if offset != 0 {
        return Packet::Fragment { source, destination };
    }
    if header[9] != PROTOCOL_UDP {
        return Packet::Other;
    }
    // Ethernet pads short frames, so the IP total length bounds the packet.
    let end = if total >= header_length { total.min(data.len()) } else { data.len() };
    let Some(payload) = data.get(header_length..end) else { return Packet::Other };
    udp(source, destination, payload, more_fragments, total as u32)
}

fn ipv6(data: &[u8]) -> Packet<'_> {
    let Some(header) = data.get(..40) else { return Packet::Other };
    if header[0] >> 4 != 6 {
        return Packet::Other;
    }
    let payload_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let mut next = header[6];
    let octets = |range: std::ops::Range<usize>| -> [u8; 16] { header[range].try_into().expect("16 octets") };
    let source = IpAddr::V6(Ipv6Addr::from(octets(8..24)));
    let destination = IpAddr::V6(Ipv6Addr::from(octets(24..40)));
    let end = (40 + payload_length).min(data.len());
    let mut rest = &data[40..end];
    let mut fragmented = false;
    // Extension headers: hop-by-hop, routing, fragment, authentication and destination options.
    loop {
        match next {
            0 | 43 | 60 => {
                let Some(ext) = rest.get(..2) else { return Packet::Other };
                let length = (usize::from(ext[1]) + 1) * 8;
                next = ext[0];
                let Some(after) = rest.get(length..) else { return Packet::Other };
                rest = after;
            }
            51 => {
                let Some(ext) = rest.get(..2) else { return Packet::Other };
                let length = (usize::from(ext[1]) + 2) * 4;
                next = ext[0];
                let Some(after) = rest.get(length..) else { return Packet::Other };
                rest = after;
            }
            44 => {
                let Some(ext) = rest.get(..8) else { return Packet::Other };
                let offset = u16::from_be_bytes([ext[2], ext[3]]) >> 3;
                if offset != 0 {
                    return Packet::Fragment { source, destination };
                }
                fragmented = ext[3] & 1 != 0;
                next = ext[0];
                rest = &rest[8..];
            }
            PROTOCOL_UDP => return udp(source, destination, rest, fragmented, 40 + payload_length as u32),
            _ => return Packet::Other,
        }
    }
}

fn udp(source: IpAddr, destination: IpAddr, data: &[u8], fragmented: bool, ip_length: u32) -> Packet<'_> {
    let Some(header) = data.get(..8) else { return Packet::Other };
    let length = u16::from_be_bytes([header[4], header[5]]);
    let end = usize::from(length).max(8).min(data.len());
    Packet::Udp(Datagram {
        source: SocketAddr::new(source, u16::from_be_bytes([header[0], header[1]])),
        destination: SocketAddr::new(destination, u16::from_be_bytes([header[2], header[3]])),
        length,
        payload: &data[8..end],
        fragmented,
        ip_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(flags: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut ip = vec![0x45, 0xB8];
        ip.extend((total as u16).to_be_bytes());
        ip.extend([0, 1]);
        ip.extend(flags.to_be_bytes());
        ip.extend([64, 17, 0, 0, 192, 168, 1, 10, 239, 1, 1, 1]);
        ip.extend(5004_u16.to_be_bytes());
        ip.extend(5006_u16.to_be_bytes());
        ip.extend(((8 + payload.len()) as u16).to_be_bytes());
        ip.extend([0, 0]);
        ip.extend(payload);
        ip
    }

    fn ethernet(ethertype: &[u8], body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x01, 0x00, 0x5E, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        frame.extend(ethertype);
        frame.extend(body);
        frame
    }

    #[test]
    fn reads_udp_over_ethernet_and_vlans() {
        let ip = ipv4_udp(0x4000, b"payload");
        for frame in [
            ethernet(&[0x08, 0x00], &ip),
            ethernet(&[0x81, 0x00, 0x00, 0x64, 0x08, 0x00], &ip),
            ethernet(&[0x88, 0xA8, 0x00, 0x0A, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00], &ip),
        ] {
            let Packet::Udp(d) = parse(capture::ETHERNET, &frame) else { panic!("a datagram") };
            assert_eq!(d.source, "192.168.1.10:5004".parse().unwrap());
            assert_eq!(d.destination, "239.1.1.1:5006".parse().unwrap());
            assert_eq!((d.payload, d.length, d.ip_length), (&b"payload"[..], 15, 35));
            assert!(d.complete() && !d.fragmented);
        }
        // Ethernet padding after a short packet is not payload.
        let mut padded = ethernet(&[0x08, 0x00], &ipv4_udp(0, b"x"));
        padded.extend([0; 17]);
        let Packet::Udp(d) = parse(capture::ETHERNET, &padded) else { panic!("a datagram") };
        assert_eq!(d.payload, b"x");
        // Raw IP and a cooked capture.
        assert!(matches!(parse(capture::RAW, &ip), Packet::Udp(_)));
        let mut sll = vec![0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, 0x08, 0x00];
        sll.extend(&ip);
        assert!(matches!(parse(capture::LINUX_SLL, &sll), Packet::Udp(_)));
    }

    #[test]
    fn tells_fragments_apart() {
        let first = ipv4_udp(0x2000, b"part one");
        let Packet::Udp(d) = parse(capture::RAW, &first) else { panic!("a datagram") };
        assert!(d.fragmented && !d.complete());
        let later = ipv4_udp(0x00B9, b"part two");
        assert!(matches!(parse(capture::RAW, &later), Packet::Fragment { .. }));
    }

    #[test]
    fn reads_ipv6_and_layer_2_ptp() {
        let mut ip = vec![0x60, 0, 0, 0, 0, 24, 0, 1];
        ip.extend([0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend([0xFF, 0x0E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x81]);
        // A hop-by-hop options header, then UDP.
        ip.extend([17, 0, 0, 0, 0, 0, 0, 0]);
        ip.extend([0x01, 0x3F, 0x01, 0x3F, 0, 16, 0, 0]);
        ip.extend(b"8 octets");
        let frame = ethernet(&[0x86, 0xDD], &ip);
        let Packet::Udp(d) = parse(capture::ETHERNET, &frame) else { panic!("a datagram") };
        assert_eq!(d.destination, "[ff0e::181]:319".parse().unwrap());
        assert_eq!(d.payload, b"8 octets");

        let frame = ethernet(&[0x88, 0xF7], b"ptp");
        assert_eq!(parse(capture::ETHERNET, &frame), Packet::Ptp { source: [2, 0, 0, 0, 0, 1], payload: b"ptp" });
        assert_eq!(parse(capture::ETHERNET, &frame[..10]), Packet::Other);
        assert_eq!(parse(capture::ETHERNET, &ethernet(&[0x08, 0x06], &[0; 28])), Packet::Other);
    }
}
