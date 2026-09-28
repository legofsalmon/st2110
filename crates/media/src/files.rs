//! Files: PNG pictures of frames, WAV files of audio, and pcap captures of packets.

use std::io::{self, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::send::Output;

const NANOS: i128 = 1_000_000_000;

/// The CRC-32 of PNG chunks and Ethernet frames (ISO 3309), one bit at a time.
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    for part in parts {
        for &byte in *part {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
    }
    !crc
}

/// Writes a picture of `width × height` 8-bit R'G'B' triplets as a PNG file. The image
/// data is stored, not compressed: a 1080p frame makes about 6 MB.
pub fn write_png(out: &mut impl Write, width: u32, height: u32, rgb: &[u8]) -> io::Result<()> {
    let row = 3 * width as usize;
    if width == 0 || height == 0 || rgb.len() != row * height as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the picture's size does not match its pixels"));
    }
    let chunk = |out: &mut dyn Write, kind: &[u8; 4], data: &[u8]| -> io::Result<()> {
        out.write_all(&(data.len() as u32).to_be_bytes())?;
        out.write_all(kind)?;
        out.write_all(data)?;
        out.write_all(&crc32(&[kind, data]).to_be_bytes())
    };
    out.write_all(b"\x89PNG\r\n\x1a\n")?;
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    // 8 bits, truecolour, deflate, adaptive filters, no interlace.
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(out, b"IHDR", &header)?;
    // Each row after filter type 0, in stored deflate blocks of at most 65 535 octets,
    // inside a zlib stream with its Adler-32.
    let mut raw = Vec::with_capacity((row + 1) * height as usize);
    for line in rgb.chunks_exact(row) {
        raw.push(0);
        raw.extend_from_slice(line);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in raw.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        (a, b) = (a % 65_521, b % 65_521);
    }
    let blocks = raw.chunks(65_535).count();
    let mut zlib = Vec::with_capacity(raw.len() + 5 * blocks + 6);
    zlib.extend_from_slice(&[0x78, 0x01]);
    for (i, block) in raw.chunks(65_535).enumerate() {
        zlib.push(u8::from(i + 1 == blocks));
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    chunk(out, b"IDAT", &zlib)?;
    chunk(out, b"IEND", &[])
}

/// Writes interleaved PCM samples as a WAV file, filling in its sizes when finished.
pub struct WavWriter<W: Write + Seek> {
    out: W,
    bytes: usize,
    written: u64,
}

impl<W: Write + Seek> WavWriter<W> {
    /// Starts a WAV file of `channels` channels of `bits`-bit samples at `rate` Hz.
    pub fn new(mut out: W, channels: u16, rate: u32, bits: u8) -> io::Result<Self> {
        let bytes = usize::from(bits / 8);
        let block = channels * u16::from(bits / 8);
        out.write_all(b"RIFF\0\0\0\0WAVEfmt ")?;
        out.write_all(&16u32.to_le_bytes())?;
        out.write_all(&1u16.to_le_bytes())?;
        out.write_all(&channels.to_le_bytes())?;
        out.write_all(&rate.to_le_bytes())?;
        out.write_all(&(rate * u32::from(block)).to_le_bytes())?;
        out.write_all(&block.to_le_bytes())?;
        out.write_all(&u16::from(bits).to_le_bytes())?;
        out.write_all(b"data\0\0\0\0")?;
        Ok(Self { out, bytes, written: 0 })
    }

    /// Adds samples, little-endian as WAV has them.
    pub fn write(&mut self, samples: &[i32]) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(samples.len() * self.bytes);
        for s in samples {
            buffer.extend_from_slice(&s.to_le_bytes()[..self.bytes]);
        }
        self.out.write_all(&buffer)?;
        self.written += buffer.len() as u64;
        Ok(())
    }

    /// Fills in the sizes, which WAV counts in 32 bits, and hands back the file.
    pub fn finish(mut self) -> io::Result<W> {
        // A chunk of odd length has a pad octet after it, which RIFF counts but the chunk
        // does not.
        let pad = (self.written % 2) as u32;
        if pad == 1 {
            self.out.write_all(&[0])?;
        }
        let data = self.written.min(u64::from(u32::MAX - 37)) as u32;
        self.out.seek(SeekFrom::Start(4))?;
        self.out.write_all(&(data + pad + 36).to_le_bytes())?;
        self.out.seek(SeekFrom::Start(40))?;
        self.out.write_all(&data.to_le_bytes())?;
        self.out.seek(SeekFrom::End(0))?;
        Ok(self.out)
    }
}

/// Writes a pcap file of UDP datagrams in Ethernet and IPv4, with nanosecond timestamps.
pub struct PcapWriter<W: Write> {
    out: W,
    ident: u16,
    frame: Vec<u8>,
}

impl<W: Write> PcapWriter<W> {
    /// Starts a capture.
    pub fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&0xA1B2_3C4Du32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&[0; 8])?;
        out.write_all(&65_535u32.to_le_bytes())?;
        out.write_all(&1u32.to_le_bytes())?;
        Ok(Self { out, ident: 0, frame: Vec::with_capacity(1600) })
    }

    /// Adds a datagram captured at `at` nanoseconds since 1970 on the capture's clock.
    pub fn udp(
        &mut self,
        at: i128,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let f = &mut self.frame;
        f.clear();
        let dst = destination.ip().octets();
        if destination.ip().is_multicast() {
            f.extend_from_slice(&[0x01, 0x00, 0x5E, dst[1] & 0x7F, dst[2], dst[3]]);
        } else {
            f.extend_from_slice(&[0x02, 0, dst[0], dst[1], dst[2], dst[3]]);
        }
        let src = source.ip().octets();
        f.extend_from_slice(&[0x02, 0, src[0], src[1], src[2], src[3]]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let ip_length = (20 + 8 + payload.len()) as u16;
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_length.to_be_bytes());
        ip[4..6].copy_from_slice(&self.ident.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = ttl;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        let sum: u32 = ip.as_chunks::<2>().0.iter().map(|&w| u32::from(u16::from_be_bytes(w))).sum();
        let folded = (sum & 0xFFFF) + (sum >> 16);
        ip[10..12].copy_from_slice(&(!((folded & 0xFFFF) + (folded >> 16)) as u16).to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&source.port().to_be_bytes());
        f.extend_from_slice(&destination.port().to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        self.ident = self.ident.wrapping_add(1);
        let (seconds, nanos) = (at.div_euclid(NANOS), at.rem_euclid(NANOS));
        let seconds = u32::try_from(seconds)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the time does not fit a pcap file"))?;
        self.out.write_all(&seconds.to_le_bytes())?;
        self.out.write_all(&(nanos as u32).to_le_bytes())?;
        self.out.write_all(&(f.len() as u32).to_le_bytes())?;
        self.out.write_all(&(f.len() as u32).to_le_bytes())?;
        self.out.write_all(f)
    }

    /// Hands back the file.
    pub fn into_inner(self) -> W {
        self.out
    }
}

/// An [`Output`] that writes each packet into a capture at its time, once for each leg,
/// on a clock `tai_utc` seconds behind TAI as a capture on UTC is.
pub struct Capture<W: Write> {
    writer: PcapWriter<W>,
    legs: Vec<(SocketAddrV4, SocketAddrV4)>,
    ttl: u8,
    behind: i128,
}

impl<W: Write> Capture<W> {
    /// A capture of packets from and to each leg's addresses.
    pub fn new(out: W, legs: Vec<(SocketAddrV4, SocketAddrV4)>, ttl: u8, tai_utc: i32) -> io::Result<Self> {
        Ok(Self { writer: PcapWriter::new(out)?, legs, ttl, behind: i128::from(tai_utc) * NANOS })
    }

    /// Hands back the file.
    pub fn into_inner(self) -> W {
        self.writer.into_inner()
    }
}

impl<W: Write> Output for Capture<W> {
    fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()> {
        for &(source, destination) in &self.legs {
            self.writer.udp(at - self.behind, source, destination, self.ttl, packet)?;
        }
        Ok(())
    }
}

/// The address a capture shows packets coming from when the source is not known: one
/// from the documentation range (RFC 5737).
pub const UNKNOWN_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn crc_and_png() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        let mut png = Vec::new();
        write_png(&mut png, 2, 1, &[255, 0, 0, 0, 0, 255]).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[12..16], b"IHDR");
        // IDAT: zlib header, one final stored block of 7 octets, then the Adler-32.
        let idat = &png[33..];
        assert_eq!(&idat[4..8], b"IDAT");
        assert_eq!(&idat[8..15], [0x78, 0x01, 0x01, 7, 0, !7, 0xFF]);
        assert_eq!(&idat[15..22], [0, 255, 0, 0, 0, 0, 255]);
        assert_eq!(&idat[22..26], [0x07, 0x00, 0x01, 0xFF]);
        assert!(png.ends_with(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]));
        assert!(write_png(&mut Vec::new(), 2, 2, &[0; 6]).is_err());
    }

    #[test]
    fn wav() {
        let mut w = WavWriter::new(Cursor::new(Vec::new()), 2, 48_000, 24).unwrap();
        w.write(&[1, -1, 0x123456, -0x123456]).unwrap();
        let file = w.finish().unwrap().into_inner();
        assert_eq!(file.len(), 44 + 12);
        assert_eq!(&file[..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(file[4..8].try_into().unwrap()), 36 + 12);
        assert_eq!(u32::from_le_bytes(file[28..32].try_into().unwrap()), 48_000 * 6);
        assert_eq!(u32::from_le_bytes(file[40..44].try_into().unwrap()), 12);
        assert_eq!(&file[44..], [1, 0, 0, 0xFF, 0xFF, 0xFF, 0x56, 0x34, 0x12, 0xAA, 0xCB, 0xED]);
        // One 24-bit sample: three octets of data, and a pad octet.
        let mut w = WavWriter::new(Cursor::new(Vec::new()), 1, 48_000, 24).unwrap();
        w.write(&[7]).unwrap();
        let file = w.finish().unwrap().into_inner();
        assert_eq!(file.len(), 44 + 4);
        assert_eq!(u32::from_le_bytes(file[4..8].try_into().unwrap()), 36 + 4);
        assert_eq!(u32::from_le_bytes(file[40..44].try_into().unwrap()), 3);
    }

    #[test]
    fn pcap_the_analyser_reads() {
        let source: SocketAddrV4 = "10.0.0.1:5004".parse().unwrap();
        let destination: SocketAddrV4 = "239.1.2.3:5004".parse().unwrap();
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.udp(1_790_510_400 * NANOS + 5, source, destination, 32, b"hello").unwrap();
        let file = w.into_inner();
        let mut reader = st2110_pcap::Reader::new(&file[..]).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.time, 1_790_510_400 * NANOS + 5);
        let st2110_pcap::net::Packet::Udp(d) = st2110_pcap::net::parse(frame.link, frame.data) else {
            panic!("not UDP")
        };
        assert_eq!(
            (d.source, d.destination, d.payload, d.complete()),
            (source.into(), destination.into(), &b"hello"[..], true)
        );
        // The multicast MAC address, and a header checksum that sums to 0xFFFF.
        assert_eq!(frame.data[..6], [0x01, 0x00, 0x5E, 0x01, 0x02, 0x03]);
        let sum: u32 = frame.data[14..34].as_chunks::<2>().0.iter().map(|&w| u32::from(u16::from_be_bytes(w))).sum();
        assert_eq!((sum & 0xFFFF) + (sum >> 16), 0xFFFF);
    }
}
