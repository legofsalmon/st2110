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

/// How a JPEG XS frame is scanned, and which picture segment a packet is part of: the I
/// field of RFC 9134 §4.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JxsScan {
    /// Progressive (00).
    Progressive,
    /// The value 01, reserved.
    Reserved,
    /// The first picture segment (field) of an interlaced frame (10).
    First,
    /// The second picture segment (11).
    Second,
}

/// The RFC 9134 payload header that starts every ST 2110-22 JPEG XS packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JxsHeader {
    /// T: packets are sent in order.
    pub sequential: bool,
    /// K: slice packetization mode, rather than codestream mode.
    pub slice_mode: bool,
    /// L: the last packet of a packetization unit.
    pub last: bool,
    /// I: progressive, or which field.
    pub scan: JxsScan,
    /// The frame number, modulo 32.
    pub frame_counter: u8,
}

/// Reads the 4-octet payload header of RFC 9134 §4.3.
pub fn jxs_header(payload: &[u8]) -> Option<JxsHeader> {
    let b = *payload.first()?;
    payload.get(3)?;
    Some(JxsHeader {
        sequential: b & 0x80 != 0,
        slice_mode: b & 0x40 != 0,
        last: b & 0x20 != 0,
        scan: match (b >> 3) & 0b11 {
            0b00 => JxsScan::Progressive,
            0b01 => JxsScan::Reserved,
            0b10 => JxsScan::First,
            _ => JxsScan::Second,
        },
        frame_counter: ((b & 0b111) << 2) | (payload[1] >> 6),
    })
}

/// One sample row data header of an ST 2110-20 payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleRow {
    /// Octets of sample data.
    pub length: u16,
    /// The F bit.
    pub second_field: bool,
    /// The row number.
    pub row: u16,
    /// The offset of the first pixel in the row.
    pub offset: u16,
}

/// The sample row data headers of an ST 2110-20 payload, as many as the C bits chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleRows {
    /// The first three headers; ST 2110-20 allows no more.
    pub rows: [Option<SampleRow>; 3],
    /// Whether the third header's C bit says that a fourth follows.
    pub more: bool,
}

impl SampleRows {
    /// The headers, in order.
    pub fn iter(&self) -> impl Iterator<Item = SampleRow> + '_ {
        self.rows.iter().flatten().copied()
    }

    /// Octets of the payload header: the extended sequence number and the headers.
    pub fn header_length(&self) -> usize {
        2 + 6 * self.iter().count()
    }
}

/// Reads every sample row data header of an ST 2110-20 payload, up to three (ST
/// 2110-20:2022 §6.1.4). `None` when `payload` ends before the last one the C bits
/// promise.
pub fn sample_rows(payload: &[u8]) -> Option<SampleRows> {
    let mut rows = [None; 3];
    let mut at = 2;
    for (i, slot) in rows.iter_mut().enumerate() {
        let h = payload.get(at..at + 6)?;
        at += 6;
        *slot = Some(SampleRow {
            length: u16::from_be_bytes([h[0], h[1]]),
            second_field: h[2] & 0x80 != 0,
            row: u16::from_be_bytes([h[2] & 0x7F, h[3]]),
            offset: u16::from_be_bytes([h[4] & 0x7F, h[5]]),
        });
        if h[4] & 0x80 == 0 {
            return Some(SampleRows { rows, more: false });
        }
        if i == 2 {
            return Some(SampleRows { rows, more: true });
        }
    }
    unreachable!("the loop returns on its third pass")
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

/// The value of an RFC 8331 payload header's 22 reserved bits, which are 0.
pub fn anc_reserved(payload: &[u8]) -> Option<u32> {
    let b = payload.get(5..8)?;
    Some(u32::from(b[0] & 0x3F) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]))
}

/// The Line_Number that RFC 8331 §2.1 reserves for a packet with no line given, and the
/// one for any line from two after the switching line to the last before active video.
pub const ANC_ANY_LINE: u16 = 0x7FF;
/// See [`ANC_ANY_LINE`].
pub const ANC_VANC_LINE: u16 = 0x7FE;
/// The Line_Number of a line too high for 11 bits.
pub const ANC_HIGH_LINE: u16 = 0x7FD;
/// Horizontal_Offset values from this one up name a region, not an offset.
pub const ANC_REGION_OFFSET: u16 = 0xFFC;

/// One SMPTE ST 291-1 ANC data packet in an RFC 8331 payload, its words as they arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncPacket {
    /// C: the colour-difference data channel, rather than luma.
    pub chroma: bool,
    /// The digital interface line, or one of the codes from [`ANC_HIGH_LINE`] up.
    pub line: u16,
    /// Words from SAV, or one of the codes from [`ANC_REGION_OFFSET`] up.
    pub horizontal: u16,
    /// StreamNum, when the S bit says one is given.
    pub stream: Option<u8>,
    /// The 10-bit DID word.
    pub did: u16,
    /// The 10-bit SDID word, or DBN of a Type 1 packet.
    pub sdid: u16,
    /// The 10-bit Data_Count word.
    pub data_count: u16,
    /// The user data words.
    pub user_data: Vec<u16>,
    /// The 10-bit checksum word.
    pub checksum: u16,
}

impl AncPacket {
    /// Whether the packet proposes an exact line or data stream, which ST 2110-40:2023
    /// §5.2.2 says needs a `VPID_Code`: a Line_Number other than 0x7FE and 0x7FF, or a
    /// stream number.
    pub fn exact_location(&self) -> bool {
        !matches!(self.line, ANC_VANC_LINE | ANC_ANY_LINE) || self.stream.is_some()
    }

    /// What is wrong with its words, by ST 291-1:2011 §6 and RFC 8331 §2.1: b8 of the
    /// DID, SDID or DBN, and Data_Count is the even parity of b7 to b0, b9 is NOT b8, and
    /// the checksum is the 9-bit sum of the words from the DID to the last user data
    /// word, with its b9 NOT b8.
    pub fn word_problem(&self) -> Option<String> {
        for (name, word) in [("DID", self.did), ("SDID", self.sdid), ("Data_Count", self.data_count)] {
            if !parity_word(word) {
                return Some(format!("its {name} word {word:#05X} has the wrong parity bits"));
            }
        }
        let sum = [self.did, self.sdid, self.data_count]
            .iter()
            .chain(&self.user_data)
            .fold(0_u16, |sum, word| sum.wrapping_add(word & 0x1FF))
            & 0x1FF;
        let expected = sum | if sum & 0x100 == 0 { 0x200 } else { 0 };
        (self.checksum != expected)
            .then(|| format!("its checksum word is {:#05X}, not the {expected:#05X} its words sum to", self.checksum))
    }

    /// The DID and the SDID as `DID_SDID` names them: a Type 1 packet, whose DID has b7
    /// set, has a DBN in place of the SDID and is listed with SDID 0x00 (RFC 8331 §3.1).
    pub fn type_id(&self) -> (u8, u8) {
        let did = (self.did & 0xFF) as u8;
        (did, if did & 0x80 != 0 { 0 } else { (self.sdid & 0xFF) as u8 })
    }
}

/// A 10-bit word whose b8 is the even parity of b7 to b0 and whose b9 is NOT b8.
fn parity_word(word: u16) -> bool {
    let b8 = (word & 0xFF).count_ones() % 2 == 1;
    (word & 0x100 != 0) == b8 && (word & 0x200 != 0) != b8
}

/// Reads `count` ANC data packets from `data`, the RFC 8331 payload after its 8-octet
/// header, as far as the Length field counts. Each packet starts on a 32-bit word and
/// ends with the bits that complete its last word. `Err` says how the packets fail to
/// fill `data` exactly.
pub fn anc_packets(data: &[u8], count: u8) -> Result<Vec<AncPacket>, String> {
    let mut bits = Bits { data, at: 0 };
    let mut packets = Vec::with_capacity(usize::from(count));
    for n in 1..=count {
        let packet = (|| {
            let chroma = bits.read(1)? == 1;
            let line = bits.read(11)? as u16;
            let horizontal = bits.read(12)? as u16;
            let given = bits.read(1)? == 1;
            let stream = bits.read(7)? as u8;
            let did = bits.read(10)? as u16;
            let sdid = bits.read(10)? as u16;
            let data_count = bits.read(10)? as u16;
            let user_data = (0..data_count & 0xFF).map(|_| bits.read(10).map(|w| w as u16)).collect::<Option<_>>()?;
            let checksum = bits.read(10)? as u16;
            bits.align()?;
            Some(AncPacket {
                chroma,
                line,
                horizontal,
                stream: given.then_some(stream),
                did,
                sdid,
                data_count,
                user_data,
                checksum,
            })
        })();
        match packet {
            Some(packet) => packets.push(packet),
            None => return Err(format!("ANC packet {n} of {count} runs past the {} octets of data", data.len())),
        }
    }
    let used = bits.at / 8;
    if used != data.len() {
        return Err(format!("the ANC packets fill {used} of its {} octets", data.len()));
    }
    Ok(packets)
}

/// Reads bits, most significant first.
struct Bits<'a> {
    data: &'a [u8],
    at: usize,
}

impl Bits<'_> {
    fn read(&mut self, n: usize) -> Option<u32> {
        if self.at + n > self.data.len() * 8 {
            return None;
        }
        let mut value = 0;
        for _ in 0..n {
            let bit = self.data[self.at / 8] >> (7 - self.at % 8) & 1;
            value = value << 1 | u32::from(bit);
            self.at += 1;
        }
        Some(value)
    }

    /// Skips to the next 32-bit word, if the bits that complete this one are there.
    fn align(&mut self) -> Option<()> {
        let to = self.at.div_ceil(32) * 32;
        (to <= self.data.len() * 8).then(|| self.at = to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 10-bit word: the octet with its parity bits.
    fn word(value: u8) -> u16 {
        let b8 = u16::from(value.count_ones() % 2 == 1);
        u16::from(value) | b8 << 8 | (b8 ^ 1) << 9
    }

    /// Packs the header and words of one ANC packet, word-aligned.
    fn pack(header: u32, words: &[u16]) -> Vec<u8> {
        let mut bits: Vec<bool> = (0..32).rev().map(|i| header >> i & 1 == 1).collect();
        for w in words {
            bits.extend((0..10).rev().map(|i| w >> i & 1 == 1));
        }
        bits.resize(bits.len().div_ceil(32) * 32, false);
        bits.chunks(8).map(|byte| byte.iter().fold(0, |b, &bit| b << 1 | u8::from(bit))).collect()
    }

    #[test]
    fn reads_anc_packets() {
        // A Type 2 packet on line 9 of the luma channel: DID 0x61, SDID 0x01, two words.
        let (did, sdid, dc) = (word(0x61), word(0x01), word(2));
        let udw = [word(0x96), word(0x69)];
        let sum = [did, sdid, dc, udw[0], udw[1]].iter().fold(0, |s, w| s + (w & 0x1FF)) & 0x1FF;
        let checksum = sum | if sum & 0x100 == 0 { 0x200 } else { 0 };
        let data = pack(9 << 20 | 0xFFF << 8, &[did, sdid, dc, udw[0], udw[1], checksum]);
        assert_eq!(data.len(), 12);
        let packets = anc_packets(&data, 1).unwrap();
        let p = &packets[0];
        assert_eq!((p.chroma, p.line, p.horizontal, p.stream), (false, 9, 0xFFF, None));
        assert_eq!((p.type_id(), p.user_data.len(), p.word_problem()), ((0x61, 0x01), 2, None));
        assert!(p.exact_location());

        let mut bad = p.clone();
        bad.checksum ^= 1;
        assert!(bad.word_problem().unwrap().starts_with("its checksum word is"));
        bad.did = 0x061;
        assert_eq!(bad.word_problem().as_deref(), Some("its DID word 0x061 has the wrong parity bits"));

        // A Type 1 packet is listed with SDID 0x00, and 0x7FF with S set is still exact.
        let mut type1 = p.clone();
        (type1.did, type1.sdid, type1.line, type1.stream) = (word(0xE7), word(0x05), ANC_ANY_LINE, Some(0));
        assert_eq!(type1.type_id(), (0xE7, 0x00));
        assert!(type1.exact_location());
        type1.stream = None;
        assert!(!type1.exact_location());

        assert_eq!(anc_packets(&data[..8], 1).unwrap_err(), "ANC packet 1 of 1 runs past the 8 octets of data");
        let mut long = data.clone();
        long.extend([0; 4]);
        assert_eq!(anc_packets(&long, 1).unwrap_err(), "the ANC packets fill 12 of its 16 octets");
        assert_eq!(anc_packets(&[], 0), Ok(Vec::new()));
        assert_eq!(anc_reserved(&[0, 0, 0, 0, 1, 0x80, 0, 1]), Some(1));
    }

    #[test]
    fn reads_the_jpeg_xs_payload_header() {
        // T=1 K=0 L=1 I=11 F=0b10110: 1011_1101 1000_0000, then SEP and P.
        let h = jxs_header(&[0b1011_1101, 0b1000_0000, 0, 5]).unwrap();
        assert!(h.sequential && !h.slice_mode && h.last);
        assert_eq!(h.scan, JxsScan::Second);
        assert_eq!(h.frame_counter, 0b10110);
        assert_eq!(jxs_header(&[0x08, 0, 0, 0]).unwrap().scan, JxsScan::Reserved);
        assert!(jxs_header(&[0, 0, 0]).is_none());
    }

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
        let rows = sample_rows(&packet[12..]).unwrap();
        assert_eq!((rows.iter().count(), rows.more, rows.header_length()), (1, false, 8));

        // Three rows, the third of which says a fourth follows.
        let mut three = vec![0x00, 0x01];
        three.extend([0x00, 0x3C, 0x00, 0x05, 0x83, 0x48]);
        three.extend([0x00, 0x3C, 0x00, 0x06, 0x80, 0x00]);
        three.extend([0x00, 0x3C, 0x00, 0x07, 0x80, 0x00]);
        let rows = sample_rows(&three).unwrap();
        let read: Vec<(u16, u16, u16)> = rows.iter().map(|r| (r.length, r.row, r.offset)).collect();
        assert_eq!(read, [(60, 5, 840), (60, 6, 0), (60, 7, 0)]);
        assert!(rows.more);
        assert_eq!(sample_rows(&three[..14]), None);

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
