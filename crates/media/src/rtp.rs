//! RTP headers (RFC 3550).

pub(crate) use st2110_pcap::rtp::Header;

/// Writes an RTP header: version 2, with no padding, extension or contributing sources.
pub(crate) fn write_header(
    out: &mut Vec<u8>,
    marker: bool,
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
) {
    out.push(0x80);
    out.push((u8::from(marker) << 7) | (payload_type & 0x7F));
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
}

/// Reads the RTP header of a whole datagram: `None` when it is not RTP version 2, or
/// its header and padding do not fit in it.
pub(crate) fn read_header(packet: &[u8]) -> Option<Header> {
    let header = st2110_pcap::rtp::header(packet, true)?;
    (header.length + header.padding <= packet.len()).then_some(header)
}

/// The payload of a datagram whose header [`read_header`] read.
pub(crate) fn payload<'p>(packet: &'p [u8], header: &Header) -> &'p [u8] {
    &packet[header.length..packet.len() - header.padding]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_what_it_reads() {
        let mut out = Vec::new();
        write_header(&mut out, true, 97, 0xFFFE, 48_000, 7);
        out.extend_from_slice(&[1, 2, 3]);
        let h = read_header(&out).unwrap();
        assert_eq!((h.marker, h.payload_type, h.sequence, h.timestamp, h.ssrc), (true, 97, 0xFFFE, 48_000, 7));
        assert_eq!(payload(&out, &h), [1, 2, 3]);
        // Fifteen contributing sources that are not there.
        out[0] = 0x8F;
        assert!(read_header(&out).is_none());
        // Padding longer than the packet.
        out[0] = 0xA0;
        *out.last_mut().unwrap() = 200;
        assert!(read_header(&out).is_none());
    }
}
