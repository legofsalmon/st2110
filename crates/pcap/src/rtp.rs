//! RTP headers (RFC 3550) and the payload headers of ST 2110-20 video and ST 2110-40
//! ancillary data.

/// The fixed and variable parts of an RTP header that the measurements use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The marker bit.
    pub marker: bool,
    /// The payload type.
    pub payload_type: u8,
    /// The sequence number.
    pub sequence: u16,
    /// The timestamp.
    pub timestamp: u32,
    /// The synchronisation source.
    pub ssrc: u32,
    /// Octets of header: the fixed 12, the CSRC list and any extension.
    pub length: usize,
    /// Octets of padding at the end of the packet, when the padding bit is set and the
    /// whole packet was captured.
    pub padding: usize,
}

/// Reads the RTP header at the start of a UDP payload. `None` when it is not RTP
/// version 2, is RTCP, or is too short. `complete` says whether the whole datagram was
/// captured, without which the padding count in its last octet cannot be read.
pub fn header(bytes: &[u8], complete: bool) -> Option<Header> {
    let fixed = bytes.get(..12)?;
    if fixed[0] >> 6 != 2 {
        return None;
    }
    // RTCP sender and receiver reports and the rest (200 to 204) share the port range
    // and the version; read as RTP they have the marker set and types 72 to 76.
    if (200..=204).contains(&fixed[1]) {
        return None;
    }
    let csrcs = usize::from(fixed[0] & 0x0F);
    let mut length = 12 + 4 * csrcs;
    if fixed[0] & 0x10 != 0 {
        let extension = bytes.get(length..length + 4)?;
        length += 4 + 4 * usize::from(u16::from_be_bytes([extension[2], extension[3]]));
    }
    let padding = match (fixed[0] & 0x20 != 0, complete) {
        (true, true) => usize::from(*bytes.last()?),
        _ => 0,
    };
    Some(Header {
        marker: fixed[1] & 0x80 != 0,
        payload_type: fixed[1] & 0x7F,
        sequence: u16::from_be_bytes([fixed[2], fixed[3]]),
        timestamp: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        ssrc: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
        length,
        padding,
    })
}

/// The start of an ST 2110-20 payload header: the extended sequence number and the
/// first sample row data header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VideoHeader {
    /// The high 16 bits of the 32-bit sequence number.
    pub extended_sequence: u16,
    /// Octets of sample data in the first row segment.
    pub length: u16,
    /// The F bit: the second field of an interlaced frame, or the second segment of PsF.
    pub second_field: bool,
    /// The row number, counting from 0 at the top of the image or field.
    pub row: u16,
    /// The C bit: another sample row data header follows.
    pub continuation: bool,
    /// The offset of the first pixel of the segment in the row.
    pub offset: u16,
}

/// Reads the first 8 octets of an ST 2110-20 payload (ST 2110-20:2022 §6.1).
pub fn video_header(payload: &[u8]) -> Option<VideoHeader> {
    let b = payload.get(..8)?;
    Some(VideoHeader {
        extended_sequence: u16::from_be_bytes([b[0], b[1]]),
        length: u16::from_be_bytes([b[2], b[3]]),
        second_field: b[4] & 0x80 != 0,
        row: u16::from_be_bytes([b[4] & 0x7F, b[5]]),
        continuation: b[6] & 0x80 != 0,
        offset: u16::from_be_bytes([b[6] & 0x7F, b[7]]),
    })
}

/// Which field an ST 2110-40 packet's data belongs to: the F field of RFC 8331 §2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AncField {
    /// Progressive video, or no field given (00).
    Progressive,
    /// The first field of interlaced video (10).
    First,
    /// The second field (11).
    Second,
    /// The value 01, which RFC 8331 does not allow.
    Invalid,
}

/// The start of an ST 2110-40 (RFC 8331) payload header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AncHeader {
    /// The high 16 bits of the 32-bit sequence number.
    pub extended_sequence: u16,
    /// Octets of ANC data after the payload header.
    pub length: u16,
    /// The number of ANC data packets in the RTP packet.
    pub count: u8,
    /// The field the data belongs to.
    pub field: AncField,
}

/// Reads the first 8 octets of an RFC 8331 payload.
pub fn anc_header(payload: &[u8]) -> Option<AncHeader> {
    let b = payload.get(..8)?;
    Some(AncHeader {
        extended_sequence: u16::from_be_bytes([b[0], b[1]]),
        length: u16::from_be_bytes([b[2], b[3]]),
        count: b[4],
        field: match b[5] >> 6 {
            0b00 => AncField::Progressive,
            0b10 => AncField::First,
            0b11 => AncField::Second,
            _ => AncField::Invalid,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_headers() {
        let mut packet = vec![0x80, 0xE0, 0x12, 0x34, 0xB6, 0x7B, 0x2D, 0x62, 0xDE, 0xAD, 0xBE, 0xEF];
        packet.extend([0x00, 0x01, 0x04, 0xB0, 0x80, 0x02, 0x00, 0x10]);
        let h = header(&packet, true).unwrap();
        assert_eq!((h.marker, h.payload_type, h.sequence, h.timestamp), (true, 96, 0x1234, 3_061_525_858));
        assert_eq!((h.ssrc, h.length, h.padding), (0xDEAD_BEEF, 12, 0));
        let v = video_header(&packet[12..]).unwrap();
        assert_eq!(
            (v.extended_sequence, v.length, v.second_field, v.row, v.continuation, v.offset),
            (1, 1200, true, 2, false, 16)
        );
        // Two ANC packets in the first field.
        let anc = anc_header(&[0x00, 0x01, 0x00, 0x40, 0x02, 0x80, 0x00, 0x00]).unwrap();
        assert_eq!((anc.extended_sequence, anc.length, anc.count, anc.field), (1, 64, 2, AncField::First));
        assert_eq!(anc_header(&[0, 0, 0, 0, 0, 0x40, 0, 0]).unwrap().field, AncField::Invalid);
        assert_eq!(anc_header(&[0; 7]), None);

        // Two CSRCs, an extension of one word, and four octets of padding.
        let mut rich = vec![0xB2, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        rich.extend([0; 8]);
        rich.extend([0xBE, 0xDE, 0, 1, 0, 0, 0, 0]);
        rich.extend([1, 2, 3, 0, 0, 0, 4]);
        let h = header(&rich, true).unwrap();
        assert_eq!((h.length, h.padding, h.marker), (28, 4, false));
        assert_eq!(header(&rich, false).unwrap().padding, 0);
    }

    #[test]
    fn refuses_what_is_not_rtp() {
        assert_eq!(header(&[0x80, 0x60, 0, 1], true), None);
        assert_eq!(header(&[0x40; 12], true), None);
        // An RTCP sender report.
        assert_eq!(header(&[0x80, 200, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0], true), None);
        // An extension that runs past the end.
        assert_eq!(header(&[0x90, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xBE], true), None);
    }
}
