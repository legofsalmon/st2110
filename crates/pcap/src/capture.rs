//! Packet capture files: pcap, with microsecond or nanosecond timestamps in either byte
//! order, and pcapng.

use std::fmt;
use std::io::{self, Read};

/// A frame's link-layer header type: a LINKTYPE value from the tcpdump registry.
pub type LinkType = u16;

/// Ethernet (LINKTYPE_ETHERNET).
pub const ETHERNET: LinkType = 1;
/// A raw IPv4 or IPv6 packet (LINKTYPE_RAW).
pub const RAW: LinkType = 101;
/// Linux "cooked" capture, version 1 (LINKTYPE_LINUX_SLL).
pub const LINUX_SLL: LinkType = 113;
/// A raw IPv4 packet (LINKTYPE_IPV4).
pub const IPV4: LinkType = 228;
/// A raw IPv6 packet (LINKTYPE_IPV6).
pub const IPV6: LinkType = 229;
/// Linux "cooked" capture, version 2 (LINKTYPE_LINUX_SLL2).
pub const LINUX_SLL2: LinkType = 276;

/// The most one record or block may hold. A frame is at most 64 KiB; far larger means
/// the file is damaged.
const MAX_RECORD: usize = 16 << 20;

const NANOS: i128 = 1_000_000_000;

/// The file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// pcap.
    Pcap {
        /// Whether timestamps count nanoseconds rather than microseconds.
        nanoseconds: bool,
    },
    /// pcapng.
    PcapNg,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pcap { nanoseconds: false } => "pcap",
            Self::Pcap { nanoseconds: true } => "pcap (nanosecond)",
            Self::PcapNg => "pcapng",
        })
    }
}

/// A frame as the capture recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// When it was captured: nanoseconds since 1970-01-01 00:00:00 on the capturing clock.
    pub time: i128,
    /// Its link-layer header type.
    pub link: LinkType,
    /// The bytes captured: fewer than `length` when the capture cut the frame short.
    pub data: &'a [u8],
    /// The frame's length on the wire.
    pub length: u32,
}

/// Why a capture could not be read, or could not be read to the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// The file does not start like a pcap or pcapng file.
    NotACapture,
    /// The file ends partway through a packet or block.
    Truncated,
    /// A length or field that cannot be right.
    Malformed(String),
    /// Reading the file failed.
    Io(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACapture => f.write_str("not a pcap or pcapng file"),
            Self::Truncated => f.write_str("the file ends partway through a packet"),
            Self::Malformed(message) | Self::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// How finely an interface's timestamps count: 10⁻ⁿ or 2⁻ⁿ of a second.
#[derive(Clone, Copy, Debug)]
enum Resolution {
    Decimal(u8),
    Binary(u8),
}

impl Resolution {
    fn nanos(self, ticks: u64) -> i128 {
        let ticks = i128::from(ticks);
        match self {
            Self::Decimal(n) if n <= 9 => ticks * 10_i128.pow(u32::from(9 - n)),
            // Finer than a nanosecond: at most 10⁻¹⁹, so the power fits.
            Self::Decimal(n) => ticks / 10_i128.pow(u32::from(n - 9)),
            Self::Binary(n) => (ticks * NANOS) >> n,
        }
    }
}

/// A pcapng interface.
#[derive(Clone, Copy, Debug)]
struct Interface {
    link: LinkType,
    resolution: Resolution,
    /// if_tsoffset: seconds to add to every timestamp.
    offset: i64,
}

#[derive(Debug)]
enum Kind {
    Pcap { big_endian: bool, nanoseconds: bool, link: LinkType },
    PcapNg { big_endian: bool, interfaces: Vec<Interface> },
}

/// Where the last frame read sits in the buffer.
struct Found {
    time: i128,
    link: LinkType,
    start: usize,
    end: usize,
    length: u32,
}

/// Reads frames from a capture, one at a time, without holding the file in memory.
///
/// ```
/// use st2110_pcap::capture::Reader;
///
/// // A pcap file header with no packets.
/// let empty = [
///     0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
/// ];
/// let mut reader = Reader::new(&empty[..]).unwrap();
/// assert!(reader.next_frame().is_none());
/// ```
#[derive(Debug)]
pub struct Reader<R> {
    input: R,
    kind: Kind,
    buffer: Vec<u8>,
    done: bool,
}

impl<R: Read> Reader<R> {
    /// Reads the file header.
    pub fn new(mut input: R) -> Result<Self, CaptureError> {
        let mut magic = [0; 4];
        if !fill(&mut input, &mut magic).map_err(|_| CaptureError::NotACapture)? {
            return Err(CaptureError::NotACapture);
        }
        let pcap = |big_endian, nanoseconds| (big_endian, nanoseconds);
        let (big_endian, nanoseconds) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => pcap(false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => pcap(true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => pcap(false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => pcap(true, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                let mut reader = Self {
                    input,
                    kind: Kind::PcapNg { big_endian: false, interfaces: Vec::new() },
                    buffer: Vec::new(),
                    done: false,
                };
                reader.section_header()?;
                return Ok(reader);
            }
            _ => return Err(CaptureError::NotACapture),
        };
        let mut header = [0; 20];
        if !fill(&mut input, &mut header)? {
            return Err(CaptureError::Truncated);
        }
        // The link type is the low 16 bits; the high bits can describe the FCS.
        let link = (u32_at(&header, 16, big_endian) & 0xffff) as LinkType;
        Ok(Self { input, kind: Kind::Pcap { big_endian, nanoseconds, link }, buffer: Vec::new(), done: false })
    }

    /// The file format.
    pub fn format(&self) -> Format {
        match self.kind {
            Kind::Pcap { nanoseconds, .. } => Format::Pcap { nanoseconds },
            Kind::PcapNg { .. } => Format::PcapNg,
        }
    }

    /// The next frame, `None` at the end of the file, or why the rest cannot be read.
    /// After an error, returns `None`.
    pub fn next_frame(&mut self) -> Option<Result<Frame<'_>, CaptureError>> {
        if self.done {
            return None;
        }
        let found = match self.kind {
            Kind::Pcap { .. } => self.next_record(),
            Kind::PcapNg { .. } => self.next_packet_block(),
        };
        match found {
            Ok(Some(f)) => {
                Some(Ok(Frame { time: f.time, link: f.link, data: &self.buffer[f.start..f.end], length: f.length }))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }

    fn next_record(&mut self) -> Result<Option<Found>, CaptureError> {
        let Kind::Pcap { big_endian, nanoseconds, link } = self.kind else { unreachable!("a pcap reader") };
        let mut header = [0; 16];
        if !fill(&mut self.input, &mut header)? {
            return Ok(None);
        }
        let seconds = i128::from(u32_at(&header, 0, big_endian));
        let fraction = i128::from(u32_at(&header, 4, big_endian));
        let captured = u32_at(&header, 8, big_endian) as usize;
        let length = u32_at(&header, 12, big_endian);
        if captured > MAX_RECORD {
            return Err(CaptureError::Malformed(format!("a packet record claims {captured} captured bytes")));
        }
        self.read_body(captured)?;
        let time = seconds * NANOS + if nanoseconds { fraction } else { fraction * 1000 };
        Ok(Some(Found { time, link, start: 0, end: captured, length }))
    }

    /// Reads a Section Header Block whose type has been read.
    fn section_header(&mut self) -> Result<(), CaptureError> {
        let mut head = [0; 8];
        if !fill(&mut self.input, &mut head)? {
            return Err(CaptureError::Truncated);
        }
        let big_endian = match head[4..8] {
            [0x1a, 0x2b, 0x3c, 0x4d] => true,
            [0x4d, 0x3c, 0x2b, 0x1a] => false,
            _ => return Err(CaptureError::Malformed("a pcapng section header with no byte-order magic".into())),
        };
        let total = u32_at(&head, 0, big_endian) as usize;
        if total < 28 || !total.is_multiple_of(4) || total > MAX_RECORD {
            return Err(CaptureError::Malformed(format!("a pcapng section header of {total} bytes")));
        }
        // The rest of the body and the trailing length.
        self.read_body(total - 12)?;
        self.kind = Kind::PcapNg { big_endian, interfaces: Vec::new() };
        Ok(())
    }

    fn next_packet_block(&mut self) -> Result<Option<Found>, CaptureError> {
        loop {
            let mut kind = [0; 4];
            if !fill(&mut self.input, &mut kind)? {
                return Ok(None);
            }
            if kind == [0x0a, 0x0d, 0x0d, 0x0a] {
                self.section_header()?;
                continue;
            }
            let Kind::PcapNg { big_endian, .. } = self.kind else { unreachable!("a pcapng reader") };
            let block = u32_at(&kind, 0, big_endian);
            let mut length = [0; 4];
            if !fill(&mut self.input, &mut length)? {
                return Err(CaptureError::Truncated);
            }
            let total = u32_at(&length, 0, big_endian) as usize;
            if total < 12 || !total.is_multiple_of(4) || total > MAX_RECORD {
                return Err(CaptureError::Malformed(format!("a pcapng block of {total} bytes")));
            }
            // The body and the trailing copy of the length.
            self.read_body(total - 8)?;
            let body_len = total - 12;
            match block {
                1 => self.interface(body_len, big_endian)?,
                6 => return self.packet(big_endian, body_len, 20, true).map(Some),
                2 => return self.packet(big_endian, body_len, 20, false).map(Some),
                // Simple Packet Blocks carry no timestamp; other blocks carry no packets.
                _ => {}
            }
        }
    }

    /// Reads an Interface Description Block's body, now in the buffer.
    fn interface(&mut self, body_len: usize, big_endian: bool) -> Result<(), CaptureError> {
        if body_len < 8 {
            return Err(CaptureError::Malformed("a pcapng interface description shorter than 8 bytes".into()));
        }
        let body = &self.buffer[..body_len];
        let link = u16_at(body, 0, big_endian);
        let mut interface = Interface { link, resolution: Resolution::Decimal(6), offset: 0 };
        let mut options = &body[8..];
        while options.len() >= 4 {
            let code = u16_at(options, 0, big_endian);
            let len = usize::from(u16_at(options, 2, big_endian));
            let Some(value) = options.get(4..4 + len) else { break };
            match (code, value) {
                (0, _) => break,
                (9, [resolution]) => {
                    let n = resolution & 0x7f;
                    interface.resolution = match resolution & 0x80 {
                        0 if n <= 19 => Resolution::Decimal(n),
                        0 => return Err(CaptureError::Malformed(format!("if_tsresol of 10^-{n} s"))),
                        _ if n <= 64 => Resolution::Binary(n),
                        _ => return Err(CaptureError::Malformed(format!("if_tsresol of 2^-{n} s"))),
                    };
                }
                (14, &[a, b, c, d, e, f, g, h]) => {
                    let bytes = [a, b, c, d, e, f, g, h];
                    interface.offset = if big_endian { i64::from_be_bytes(bytes) } else { i64::from_le_bytes(bytes) };
                }
                _ => {}
            }
            options = options.get(4 + len.next_multiple_of(4)..).unwrap_or_default();
        }
        if let Kind::PcapNg { interfaces, .. } = &mut self.kind {
            interfaces.push(interface);
        }
        Ok(())
    }

    /// Reads an Enhanced Packet Block, or the obsolete Packet Block, now in the buffer.
    fn packet(&self, big_endian: bool, body_len: usize, fixed: usize, enhanced: bool) -> Result<Found, CaptureError> {
        let Kind::PcapNg { interfaces, .. } = &self.kind else { unreachable!("a pcapng reader") };
        let body = &self.buffer[..body_len];
        if body.len() < fixed {
            return Err(CaptureError::Malformed("a pcapng packet block too short for its header".into()));
        }
        let id = if enhanced { u32_at(body, 0, big_endian) as usize } else { usize::from(u16_at(body, 0, big_endian)) };
        let interface = interfaces
            .get(id)
            .ok_or_else(|| CaptureError::Malformed(format!("a packet on interface {id}, which is not described")))?;
        let ticks = u64::from(u32_at(body, 4, big_endian)) << 32 | u64::from(u32_at(body, 8, big_endian));
        let captured = u32_at(body, 12, big_endian) as usize;
        let length = u32_at(body, 16, big_endian);
        if captured > body.len() - fixed {
            return Err(CaptureError::Malformed(format!("a packet block claims {captured} captured bytes")));
        }
        let time = interface.resolution.nanos(ticks) + i128::from(interface.offset) * NANOS;
        // Kept to 64-bit nanoseconds, as pcap's own times are, so later sums cannot overflow.
        if i64::try_from(time).is_err() {
            return Err(CaptureError::Malformed("a packet time outside the years 1677 to 2262".into()));
        }
        Ok(Found { time, link: interface.link, start: fixed, end: fixed + captured, length })
    }

    /// Reads `len` bytes into the buffer.
    fn read_body(&mut self, len: usize) -> Result<(), CaptureError> {
        self.buffer.resize(len, 0);
        if len > 0 && !fill(&mut self.input, &mut self.buffer)? {
            return Err(CaptureError::Truncated);
        }
        Ok(())
    }
}

/// Fills `buf`. `Ok(false)` when the input ends before its first byte, and
/// [`CaptureError::Truncated`] when it ends partway.
fn fill(input: &mut impl Read, buf: &mut [u8]) -> Result<bool, CaptureError> {
    let mut read = 0;
    while read < buf.len() {
        match input.read(&mut buf[read..]) {
            Ok(0) if read == 0 => return Ok(false),
            Ok(0) => return Err(CaptureError::Truncated),
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn u16_at(bytes: &[u8], at: usize, big_endian: bool) -> u16 {
    let b = [bytes[at], bytes[at + 1]];
    if big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }
}

fn u32_at(bytes: &[u8], at: usize, big_endian: bool) -> u32 {
    let b = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame's time, link type, bytes and length on the wire.
    type Owned = (i128, LinkType, Vec<u8>, u32);

    fn frames(bytes: &[u8]) -> (Format, Vec<Owned>, Option<CaptureError>) {
        let mut reader = Reader::new(bytes).expect("a capture");
        let mut out = Vec::new();
        let mut error = None;
        while let Some(frame) = reader.next_frame() {
            match frame {
                Ok(f) => out.push((f.time, f.link, f.data.to_vec(), f.length)),
                Err(e) => error = Some(e),
            }
        }
        (reader.format(), out, error)
    }

    fn pcap(big_endian: bool, nanoseconds: bool, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let word = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let half = |v: u16| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut out = word(if nanoseconds { 0xa1b2_3c4d } else { 0xa1b2_c3d4 }).to_vec();
        out.extend(half(2));
        out.extend(half(4));
        out.extend(word(0));
        out.extend(word(0));
        out.extend(word(65535));
        out.extend(word(1));
        for &(seconds, fraction, data) in records {
            out.extend(word(seconds));
            out.extend(word(fraction));
            out.extend(word(data.len() as u32));
            out.extend(word(data.len() as u32 + 4));
            out.extend(data);
        }
        out
    }

    #[test]
    fn reads_pcap_in_both_byte_orders_and_resolutions() {
        for big_endian in [false, true] {
            let (format, got, error) = frames(&pcap(big_endian, false, &[(1_790_510_437, 123_456, b"abc")]));
            assert_eq!(format, Format::Pcap { nanoseconds: false });
            assert_eq!(got, [(1_790_510_437_123_456_000, ETHERNET, b"abc".to_vec(), 7)]);
            assert_eq!(error, None);
            let (format, got, _) = frames(&pcap(big_endian, true, &[(1, 5, b""), (2, 999_999_999, b"x")]));
            assert_eq!(format, Format::Pcap { nanoseconds: true });
            assert_eq!(got.iter().map(|f| f.0).collect::<Vec<_>>(), [1_000_000_005, 2_999_999_999]);
        }
    }

    #[test]
    fn reports_where_a_pcap_breaks() {
        assert_eq!(Reader::new(&b"GIF89a"[..]).unwrap_err(), CaptureError::NotACapture);
        assert_eq!(Reader::new(&[0xd4, 0xc3, 0xb2, 0xa1, 2][..]).unwrap_err(), CaptureError::Truncated);
        let mut file = pcap(false, false, &[(1, 0, b"abcd"), (2, 0, b"efgh")]);
        file.truncate(file.len() - 2);
        let (_, got, error) = frames(&file);
        assert_eq!(got.len(), 1);
        assert_eq!(error, Some(CaptureError::Truncated));
        let mut huge = pcap(false, false, &[]);
        huge.extend([0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0]);
        assert!(matches!(frames(&huge).2, Some(CaptureError::Malformed(_))));
    }

    /// A pcapng block: type, body padded to 32 bits, lengths.
    fn block(big_endian: bool, kind: u32, body: &[u8]) -> Vec<u8> {
        let word = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let padded = body.len().next_multiple_of(4);
        let total = (padded + 12) as u32;
        let mut out = word(kind).to_vec();
        out.extend(word(total));
        out.extend(body);
        out.resize(8 + padded, 0);
        out.extend(word(total));
        out
    }

    fn pcapng(big_endian: bool, resolution: Option<u8>, offset: i64) -> Vec<u8> {
        let word = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let half = |v: u16| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut shb = word(0x1a2b_3c4d).to_vec();
        shb.extend(half(1));
        shb.extend(half(0));
        shb.extend([0xff; 8]);
        let mut idb = half(ETHERNET).to_vec();
        idb.extend(half(0));
        idb.extend(word(0));
        if let Some(resolution) = resolution {
            idb.extend(half(9));
            idb.extend(half(1));
            idb.extend([resolution, 0, 0, 0]);
        }
        if offset != 0 {
            idb.extend(half(14));
            idb.extend(half(8));
            idb.extend(if big_endian { offset.to_be_bytes() } else { offset.to_le_bytes() });
        }
        idb.extend([0; 4]);
        let packet = |ticks: u64, data: &[u8]| {
            let mut epb = word(0).to_vec();
            epb.extend(word((ticks >> 32) as u32));
            epb.extend(word(ticks as u32));
            epb.extend(word(data.len() as u32));
            epb.extend(word(1500));
            epb.extend(data);
            epb
        };
        let mut out = block(big_endian, 0x0a0d_0d0a, &shb);
        out.extend(block(big_endian, 1, &idb));
        out.extend(block(big_endian, 0xbad, b"a custom block"));
        out.extend(block(big_endian, 6, &packet(1_790_510_437_123_456, b"hello")));
        out.extend(block(big_endian, 3, &[0, 0, 0, 1, 7, 0, 0, 0]));
        out.extend(block(big_endian, 6, &packet(1_790_510_438_000_000, b"")));
        out
    }

    #[test]
    fn reads_pcapng() {
        for big_endian in [false, true] {
            let (format, got, error) = frames(&pcapng(big_endian, None, 0));
            assert_eq!((format, error), (Format::PcapNg, None));
            assert_eq!(
                got,
                [
                    (1_790_510_437_123_456_000, ETHERNET, b"hello".to_vec(), 1500),
                    (1_790_510_438_000_000_000, ETHERNET, Vec::new(), 1500)
                ]
            );
        }
        // Nanosecond and binary resolutions, and a seconds offset.
        let (_, got, _) = frames(&pcapng(false, Some(9), 0));
        assert_eq!(got[0].0, 1_790_510_437_123_456);
        let (_, got, _) = frames(&pcapng(true, Some(0x80 | 20), 10));
        assert_eq!(got[0].0, ((1_790_510_437_123_456_i128 * NANOS) >> 20) + 10 * NANOS);
    }

    #[test]
    fn reports_where_a_pcapng_breaks() {
        let good = pcapng(false, None, 0);
        let (_, got, error) = frames(&good[..good.len() - 3]);
        assert_eq!((got.len(), error), (1, Some(CaptureError::Truncated)));
        // A packet on an interface no block described.
        let mut bad = good.clone();
        let at = bad.windows(5).position(|w| w == b"hello").unwrap() - 20;
        bad[at] = 3;
        assert!(matches!(frames(&bad).2, Some(CaptureError::Malformed(m)) if m.contains("interface 3")));
        // Lengths that cannot be right.
        let mut odd = good;
        odd[4] = 29;
        assert!(Reader::new(&odd[..]).is_err());
        // Ticks read as whole seconds: a packet some 57 million years from now.
        let (_, got, error) = frames(&pcapng(false, Some(0), 0));
        assert!(got.is_empty());
        assert!(matches!(error, Some(CaptureError::Malformed(m)) if m.contains("the years 1677 to 2262")));
    }
}
