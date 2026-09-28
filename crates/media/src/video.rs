//! ST 2110-20 video: frames into RTP packets, and packets back into frames.

use std::sync::Arc;

use st2110_sdp::video::PixelGroup;

use crate::format::{PAYLOAD_LIMIT, Packing, VideoFormat};
use crate::rtp;

/// Octets of the extended sequence number and of one sample row data header.
const ESN: usize = 2;
const SRD: usize = 6;

/// Octets in a block of block packing mode (ST 2110-20:2022 §6.3.3), and blocks a packet.
const BLOCK: usize = 180;
const BLOCKS: usize = 7;

/// A run of pixels that a packet carries from one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The row, counting from 0 at the top.
    pub row: u16,
    /// The offset of its first pixel in the row.
    pub offset: u16,
    /// Octets of pixel groups.
    pub length: u16,
    /// Where those octets start in the frame.
    pub start: usize,
}

/// How a format's frames are cut into packets, the same for every frame.
///
/// General packing splits each row evenly into as few packets as the standard UDP size
/// limit allows, or puts up to three whole rows in a packet when they are short. Block
/// packing fills every packet but the frame's last with seven 180-octet blocks,
/// running on from row to row, with a header for each row a packet touches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    segments: Vec<Segment>,
    /// Where each packet's segments start in `segments`, and then where they end.
    bounds: Vec<usize>,
}

impl Layout {
    /// The layout of a format's frames.
    pub fn new(format: &VideoFormat) -> Result<Self, String> {
        format.check()?;
        let group = format.pixel_group().expect("checked");
        let packets = match format.packing {
            Packing::General => general(format, group),
            Packing::Block => block(format, group),
        };
        let mut layout = Self { segments: Vec::new(), bounds: vec![0] };
        for packet in packets {
            layout.segments.extend(packet);
            layout.bounds.push(layout.segments.len());
        }
        Ok(layout)
    }

    /// Packets a frame: NPACKETS.
    pub fn packets(&self) -> usize {
        self.bounds.len() - 1
    }

    /// The row segments packet `index` carries.
    pub fn segments(&self, index: usize) -> &[Segment] {
        &self.segments[self.bounds[index]..self.bounds[index + 1]]
    }

    /// Octets of RTP payload of packet `index`: the extended sequence number, the row
    /// headers and the pixel groups.
    pub fn payload_len(&self, index: usize) -> usize {
        let segments = self.segments(index);
        ESN + SRD * segments.len() + segments.iter().map(|s| usize::from(s.length)).sum::<usize>()
    }
}

fn segment(format: &VideoFormat, group: PixelGroup, start: usize, end: usize) -> Segment {
    let row = format.row_bytes();
    let (octets, pixels) = (group.octets as usize, group.pixels as usize);
    let r = start / row;
    Segment { row: r as u16, offset: ((start - r * row) / octets * pixels) as u16, length: (end - start) as u16, start }
}

fn general(format: &VideoFormat, group: PixelGroup) -> Vec<Vec<Segment>> {
    let row = format.row_bytes();
    let height = format.height as usize;
    let octets = group.octets as usize;
    // Octets of pixel groups that fit beside `headers` row headers.
    let fits = |headers: usize| (PAYLOAD_LIMIT - ESN - SRD * headers) / octets * octets;
    let mut packets = Vec::new();
    if row <= fits(1) {
        let per = (1..=3).rev().find(|&m| m * row <= fits(m)).unwrap_or(1);
        for first in (0..height).step_by(per) {
            let rows = first..(first + per).min(height);
            packets.push(rows.map(|r| segment(format, group, r * row, (r + 1) * row)).collect());
        }
        return packets;
    }
    let groups = row / octets;
    let parts = row.div_ceil(fits(1));
    let (base, extra) = (groups / parts, groups % parts);
    for r in 0..height {
        let mut at = r * row;
        for part in 0..parts {
            let length = (base + usize::from(part < extra)) * octets;
            packets.push(vec![segment(format, group, at, at + length)]);
            at += length;
        }
    }
    packets
}

fn block(format: &VideoFormat, group: PixelGroup) -> Vec<Vec<Segment>> {
    let row = format.row_bytes();
    let total = row * format.height as usize;
    // A packet may touch three rows at most, so it may hold no more than two rows' worth.
    let chunk = BLOCKS.min(2 * row / BLOCK) * BLOCK;
    let mut packets = Vec::new();
    let mut start = 0;
    while start < total {
        let end = (start + chunk).min(total);
        let mut segments = Vec::new();
        let mut at = start;
        while at < end {
            let row_end = (at / row + 1) * row;
            let to = end.min(row_end);
            segments.push(segment(format, group, at, to));
            at = to;
        }
        packets.push(segments);
        start = end;
    }
    packets
}

/// Cuts frames into RTP packets. Keeps the stream's 32-bit sequence number, whose high
/// half goes in each payload header.
#[derive(Clone, Debug)]
pub struct Packetiser {
    layout: Arc<Layout>,
    payload_type: u8,
    ssrc: u32,
    sequence: u32,
}

impl Packetiser {
    /// A packetiser for one stream.
    pub fn new(layout: Arc<Layout>, payload_type: u8, ssrc: u32, first_sequence: u32) -> Self {
        Self { layout, payload_type, ssrc, sequence: first_sequence }
    }

    /// The layout it follows.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The sequence number the next packet will carry.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Writes packet `index` of `frame` into `out`, with the frame's RTP timestamp; the
    /// last packet of the frame carries the marker bit.
    pub fn packet(&mut self, frame: &[u8], index: usize, timestamp: u32, out: &mut Vec<u8>) {
        let segments = self.layout.segments(index);
        let marker = index + 1 == self.layout.packets();
        out.clear();
        rtp::write_header(out, marker, self.payload_type, self.sequence as u16, timestamp, self.ssrc);
        out.extend_from_slice(&((self.sequence >> 16) as u16).to_be_bytes());
        for (i, s) in segments.iter().enumerate() {
            let more = if i + 1 < segments.len() { 0x8000 } else { 0 };
            out.extend_from_slice(&s.length.to_be_bytes());
            out.extend_from_slice(&s.row.to_be_bytes());
            out.extend_from_slice(&(more | s.offset).to_be_bytes());
        }
        for s in segments {
            out.extend_from_slice(&frame[s.start..s.start + usize::from(s.length)]);
        }
        self.sequence = self.sequence.wrapping_add(1);
    }
}

/// A frame the depacketiser finished: whole, or with packets missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    /// Its RTP timestamp.
    pub timestamp: u32,
    /// Packets that arrived.
    pub packets: u32,
    /// Packets that never did: those short of the packets a frame had when one last
    /// arrived whole, or before any has, the gaps in its sequence numbers and the
    /// packet with the marker bit.
    pub missing: u32,
    /// Octets of the frame that its packets covered.
    pub filled: usize,
    /// Whether its packets covered every pixel group, and the last with the marker bit
    /// arrived.
    pub whole: bool,
    /// Whether receiving cut it off, so that it could not arrive whole: the first frame
    /// since receiving started, or the sender restarted, whose first packet never came;
    /// or the last, still arriving when receiving stopped.
    pub cut: bool,
    /// When its first packet arrived, in nanoseconds.
    pub first_arrival: i128,
    /// When its last packet arrived.
    pub last_arrival: i128,
    /// The lowest and the highest 32-bit sequence numbers of its packets.
    pub first_sequence: u32,
    /// The highest.
    pub last_sequence: u32,
}

/// What the depacketiser has counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VideoCounts {
    /// Frames finished.
    pub frames: u64,
    /// Frames that arrived whole.
    pub whole: u64,
    /// Frames that the start or end of receiving cut off: not whole, but not the
    /// stream's fault.
    pub cut: u64,
    /// Packets placed in frames.
    pub packets: u64,
    /// Packets missing from frames.
    pub missing: u64,
    /// Packets for a frame already finished, left out.
    pub late: u64,
    /// Packets whose payload header does not fit the format, left out.
    pub malformed: u64,
}

struct Assembly {
    timestamp: u32,
    lowest: u32,
    highest: u32,
    marker: bool,
    /// Whether a packet brought the frame's first pixels.
    starts: bool,
    packets: u32,
    first_arrival: i128,
    last_arrival: i128,
}

/// Puts ST 2110-20 packets back together into frames of pixel groups.
///
/// Packets should come in sequence order, as a [`crate::merge::Playout`] lets them go;
/// within a frame, any order will do. The marker bit, or a packet with another RTP
/// timestamp and a later sequence number, finishes a frame, and one with another
/// timestamp and an earlier sequence number is late. A frame is whole when its packets
/// covered every pixel group; its missing packets leave the pixels of an older frame
/// where they would have gone.
pub struct Depacketiser {
    format: VideoFormat,
    group: PixelGroup,
    row_bytes: usize,
    row_groups: usize,
    frame_ns: f64,
    assembly: Option<Assembly>,
    building: Vec<u8>,
    /// A bit for each pixel group of the frame being built that a packet covered.
    coverage: Vec<u64>,
    whole: Vec<u8>,
    has_whole: bool,
    /// The sequence number after the last frame's last packet.
    after_last: Option<u32>,
    /// Whether a frame has finished since receiving started, or the stream restarted.
    started: bool,
    packets_per_frame: Option<u32>,
    counts: VideoCounts,
}

impl Depacketiser {
    /// A depacketiser for one format.
    pub fn new(format: &VideoFormat) -> Result<Self, String> {
        format.check()?;
        let group = format.pixel_group().expect("checked");
        let size = format.frame_bytes();
        let groups = size / group.octets as usize;
        Ok(Self {
            group,
            row_bytes: format.row_bytes(),
            row_groups: (format.width / group.pixels) as usize,
            frame_ns: 1e9 / format.rate.to_f64(),
            format: format.clone(),
            assembly: None,
            building: vec![0; size],
            coverage: vec![0; groups.div_ceil(64)],
            whole: vec![0; size],
            has_whole: false,
            after_last: None,
            started: false,
            packets_per_frame: None,
            counts: VideoCounts::default(),
        })
    }

    /// What it has counted.
    pub fn counts(&self) -> VideoCounts {
        self.counts
    }

    /// The last frame that arrived whole.
    pub fn last_whole(&self) -> Option<&[u8]> {
        self.has_whole.then_some(&self.whole[..])
    }

    /// Packets a frame, as the last frame that arrived whole with no gap in its
    /// sequence numbers had them.
    pub fn packets_per_frame(&self) -> Option<u32> {
        self.packets_per_frame
    }

    /// Takes one RTP packet that arrived at `at` nanoseconds, and calls `done` with each
    /// frame it finishes and its pixel groups.
    pub fn push(&mut self, at: i128, packet: &[u8], mut done: impl FnMut(&FrameInfo, &[u8])) {
        let Some(header) = rtp::read_header(packet) else {
            self.counts.malformed += 1;
            return;
        };
        let payload = rtp::payload(packet, &header);
        let Some((extended, segments, data)) = self.parse(payload) else {
            self.counts.malformed += 1;
            return;
        };
        let sequence = (u32::from(extended) << 16) | u32::from(header.sequence);
        if let Some(a) = &self.assembly
            && a.timestamp != header.timestamp
        {
            if (sequence.wrapping_sub(a.highest) as i32) <= 0 {
                self.counts.late += 1;
                return;
            }
            self.finish(&mut done, None);
        }
        if self.assembly.is_none() {
            if self.after_last.is_some_and(|after| (sequence.wrapping_sub(after) as i32) < 0) {
                self.counts.late += 1;
                return;
            }
            self.coverage.fill(0);
            self.assembly = Some(Assembly {
                timestamp: header.timestamp,
                lowest: sequence,
                highest: sequence,
                marker: false,
                starts: false,
                packets: 0,
                first_arrival: at,
                last_arrival: at,
            });
        }
        let (octets, pixels) = (self.group.octets as usize, self.group.pixels as usize);
        let mut offset = 0;
        for (row, pixel, length) in segments.into_iter().flatten() {
            let start = row * self.row_bytes + pixel / pixels * octets;
            self.building[start..start + length].copy_from_slice(&data[offset..offset + length]);
            offset += length;
            cover(&mut self.coverage, row * self.row_groups + pixel / pixels, length / octets);
        }
        let a = self.assembly.as_mut().expect("started");
        a.starts |= segments.iter().flatten().any(|&(row, pixel, _)| row == 0 && pixel == 0);
        a.packets += 1;
        if (sequence.wrapping_sub(a.lowest) as i32) < 0 {
            a.lowest = sequence;
        }
        if (sequence.wrapping_sub(a.highest) as i32) > 0 {
            a.highest = sequence;
        }
        a.first_arrival = a.first_arrival.min(at);
        a.last_arrival = a.last_arrival.max(at);
        self.counts.packets += 1;
        if header.marker {
            a.marker = true;
            self.finish(&mut done, None);
        }
    }

    /// Finishes the frame being put together, if there is one: call it when receiving
    /// stops at `end` nanoseconds, or with `None` when the stream stopped. A frame still
    /// arriving within a frame's time of the end was cut off.
    pub fn flush(&mut self, end: Option<i128>, mut done: impl FnMut(&FrameInfo, &[u8])) {
        if self.assembly.is_some() {
            self.finish(&mut done, end);
        }
    }

    /// Forgets where the stream was, after [`Depacketiser::flush`], for one that
    /// starts again: its first frame may be cut off.
    pub fn reset(&mut self) {
        self.after_last = None;
        self.started = false;
    }

    /// Reads the payload header: the extended sequence number and up to three row
    /// segments as (row, first pixel, octets), checked against the format.
    #[allow(clippy::type_complexity)]
    fn parse<'p>(&self, payload: &'p [u8]) -> Option<(u16, [Option<(usize, usize, usize)>; 3], &'p [u8])> {
        let extended = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
        let mut segments = [None; 3];
        let mut at = ESN;
        let mut total = 0;
        for (i, slot) in segments.iter_mut().enumerate() {
            let h = payload.get(at..at + SRD)?;
            at += SRD;
            let length = usize::from(u16::from_be_bytes([h[0], h[1]]));
            let second_field = h[2] & 0x80 != 0;
            let row = usize::from(u16::from_be_bytes([h[2] & 0x7F, h[3]]));
            let more = h[4] & 0x80 != 0;
            let pixel = usize::from(u16::from_be_bytes([h[4] & 0x7F, h[5]]));
            let (octets, pixels) = (self.group.octets as usize, self.group.pixels as usize);
            let fits = !second_field
                && row < self.format.height as usize
                && length % octets == 0
                && pixel % pixels == 0
                && pixel + length / octets * pixels <= self.format.width as usize;
            if !fits || (length == 0 && (i > 0 || more)) {
                return None;
            }
            if length > 0 {
                *slot = Some((row, pixel, length));
            }
            total += length;
            if !more {
                break;
            }
            if i == 2 {
                return None;
            }
        }
        let data = &payload[at..];
        (data.len() >= total).then_some((extended, segments, data))
    }

    /// Finishes the frame being put together; `end` when receiving has stopped then.
    fn finish(&mut self, done: &mut impl FnMut(&FrameInfo, &[u8]), end: Option<i128>) {
        let a = self.assembly.take().expect("a frame to finish");
        let covered: usize = self.coverage.iter().map(|w| w.count_ones() as usize).sum();
        let filled = covered * self.group.octets as usize;
        let whole = a.marker && filled == self.format.frame_bytes();
        let gaps = a.highest.wrapping_sub(a.lowest).saturating_add(1).saturating_sub(a.packets);
        if whole && gaps == 0 {
            self.packets_per_frame = Some(a.packets);
        }
        let missing = match self.packets_per_frame {
            _ if whole => 0,
            Some(per_frame) => per_frame.saturating_sub(a.packets).max(gaps),
            None => gaps + u32::from(!a.marker),
        };
        let still_arriving = end.is_some_and(|end| !a.marker && ((end - a.last_arrival) as f64) <= self.frame_ns);
        let cut = !whole && ((!self.started && !a.starts) || still_arriving);
        let info = FrameInfo {
            timestamp: a.timestamp,
            packets: a.packets,
            missing,
            filled,
            whole,
            cut,
            first_arrival: a.first_arrival,
            last_arrival: a.last_arrival,
            first_sequence: a.lowest,
            last_sequence: a.highest,
        };
        self.counts.frames += 1;
        self.counts.cut += u64::from(cut);
        self.counts.missing += u64::from(missing);
        self.started = true;
        self.after_last = Some(a.highest.wrapping_add(1));
        if whole {
            self.counts.whole += 1;
            std::mem::swap(&mut self.building, &mut self.whole);
            self.has_whole = true;
            done(&info, &self.whole);
        } else {
            done(&info, &self.building);
        }
    }
}

/// Sets `count` bits from bit `first`.
fn cover(words: &mut [u64], first: usize, count: usize) {
    let (mut at, end) = (first, first + count);
    while at < end {
        let bit = at % 64;
        let n = (64 - bit).min(end - at);
        words[at / 64] |= (u64::MAX >> (64 - n)) << bit;
        at += n;
    }
}

#[cfg(test)]
mod tests {
    use st2110_sdp::Rational;
    use st2110_sdp::video::{Depth, Sampling};

    use super::*;

    fn format(width: u32, height: u32) -> VideoFormat {
        VideoFormat::new(width, height, Rational::new(50, 1).unwrap())
    }

    #[test]
    fn general_packing_splits_rows_evenly() {
        // 1080p 4:2:2 10-bit: 4800 octets a row in four packets of 1200.
        let f = format(1920, 1080);
        let layout = Layout::new(&f).unwrap();
        assert_eq!(layout.packets(), 4320);
        assert_eq!(layout.segments(1), [Segment { row: 0, offset: 480, length: 1200, start: 1200 }]);
        assert_eq!(layout.payload_len(0), 2 + 6 + 1200);
        // 720p: 3200 octets in packets of 1070, 1065 and 1065.
        let layout = Layout::new(&format(1280, 720)).unwrap();
        let lengths: Vec<u16> = (0..3).map(|i| layout.segments(i)[0].length).collect();
        assert_eq!((layout.packets(), lengths), (2160, vec![1070, 1065, 1065]));
        // Short rows go three to a packet.
        let layout = Layout::new(&format(160, 90)).unwrap();
        assert_eq!(layout.packets(), 30);
        assert_eq!(layout.segments(29).iter().map(|s| s.row).collect::<Vec<_>>(), [87, 88, 89]);
        for f in [format(1920, 1080), format(3840, 2160), format(160, 90), format(2, 1)] {
            let layout = Layout::new(&f).unwrap();
            assert!((0..layout.packets()).all(|i| layout.payload_len(i) <= PAYLOAD_LIMIT));
            let total: usize = layout.segments.iter().map(|s| usize::from(s.length)).sum();
            assert_eq!(total, f.frame_bytes());
        }
    }

    #[test]
    fn block_packing_fills_packets_with_seven_blocks() {
        let mut f = format(1920, 1080);
        f.packing = Packing::Block;
        let layout = Layout::new(&f).unwrap();
        // 5 184 000 octets in packets of 1260, the last of 360: 4115, as RP 2110-25 counts.
        assert_eq!(layout.packets(), 4115);
        let data = |i| layout.payload_len(i) - 2 - 6 * layout.segments(i).len();
        assert!((0..4114).all(|i| data(i) == 1260));
        assert_eq!(data(4114), 360);
        // The fourth packet runs from row 0 into row 1.
        assert_eq!(
            layout.segments(3),
            [
                Segment { row: 0, offset: 1512, length: 1020, start: 3780 },
                Segment { row: 1, offset: 0, length: 240, start: 4800 }
            ]
        );
        // Rows of 200 octets: two to a block run, so packets hold two blocks and touch three rows.
        let mut narrow = format(80, 4);
        narrow.packing = Packing::Block;
        let layout = Layout::new(&narrow).unwrap();
        assert!((0..layout.packets()).all(|i| layout.segments(i).len() <= 3));
        assert_eq!(layout.payload_len(0), 2 + 6 * 2 + 360);
    }

    fn frame_of(f: &VideoFormat) -> Vec<u8> {
        (0..f.frame_bytes()).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn packets(f: &VideoFormat, frame: &[u8], timestamp: u32, sequence: u32) -> Vec<Vec<u8>> {
        let layout = Arc::new(Layout::new(f).unwrap());
        let mut p = Packetiser::new(layout.clone(), 96, 0xDEAD_BEEF, sequence);
        (0..layout.packets())
            .map(|i| {
                let mut out = Vec::new();
                p.packet(frame, i, timestamp, &mut out);
                out
            })
            .collect()
    }

    #[test]
    fn packets_carry_headers_the_analyser_reads() {
        let f = format(1920, 1080);
        let frame = frame_of(&f);
        let all = packets(&f, &frame, 1234, 0x0001_FFFF);
        let h = st2110_pcap::rtp::header(&all[0], true).unwrap();
        assert_eq!((h.marker, h.payload_type, h.sequence, h.timestamp, h.ssrc), (false, 96, 0xFFFF, 1234, 0xDEAD_BEEF));
        let v = st2110_pcap::rtp::video_header(&all[0][12..]).unwrap();
        assert_eq!((v.extended_sequence, v.length, v.row, v.offset, v.continuation), (1, 1200, 0, 0, false));
        // The sequence number carries into the extended half.
        let v = st2110_pcap::rtp::video_header(&all[1][12..]).unwrap();
        assert_eq!((v.extended_sequence, v.offset), (2, 480));
        assert!(st2110_pcap::rtp::header(all.last().unwrap(), true).unwrap().marker);
    }

    #[test]
    fn frames_come_back_whole_in_any_order() {
        for (sampling, depth, packing) in [
            (Sampling::YCbCr422, Depth::Bits10, Packing::General),
            (Sampling::YCbCr422, Depth::Bits10, Packing::Block),
            (Sampling::Rgb, Depth::Bits12, Packing::Block),
            (Sampling::Key, Depth::Bits8, Packing::General),
        ] {
            let mut f = format(320, 24);
            (f.sampling, f.depth, f.packing) = (sampling, depth, packing);
            let frame = frame_of(&f);
            let mut all = packets(&f, &frame, 9000, 10);
            // Reversed, but for the marker packet, which ends the frame.
            let marker = all.pop().unwrap();
            all.reverse();
            all.push(marker);
            let mut d = Depacketiser::new(&f).unwrap();
            let mut got = Vec::new();
            for p in &all {
                d.push(5, p, |info, data| got.push((*info, data.to_vec())));
            }
            assert_eq!(got.len(), 1, "{sampling} {packing:?}");
            assert!(got[0].0.whole, "{:?}", got[0].0);
            assert_eq!(got[0].1, frame);
            assert_eq!(d.last_whole(), Some(&frame[..]));
        }
    }

    #[test]
    fn missing_and_late_packets_are_counted() {
        let f = format(320, 24);
        let frame = frame_of(&f);
        let first = packets(&f, &frame, 0, u32::MAX - 3);
        let second = packets(&f, &frame, 1800, (u32::MAX - 3).wrapping_add(first.len() as u32));
        let mut d = Depacketiser::new(&f).unwrap();
        let mut infos = Vec::new();
        // Frame 1 loses its first packet; frame 2 loses its marker, so frame 3's timestamp finishes it.
        for p in &first[1..] {
            d.push(0, p, |info, _| infos.push(*info));
        }
        for p in &second[..second.len() - 1] {
            d.push(0, p, |info, _| infos.push(*info));
        }
        d.push(0, &first[3], |info, _| infos.push(*info));
        let third = packets(&f, &frame, 3600, 1000);
        d.push(0, &third[0], |info, _| infos.push(*info));
        assert_eq!(infos.len(), 2);
        // With its first packet gone, the first frame reads as one the receiver joined partway.
        assert_eq!(
            (infos[0].whole, infos[0].cut, infos[0].missing, infos[0].packets),
            (false, true, 0, first.len() as u32 - 1)
        );
        assert_eq!((infos[0].first_sequence, infos[0].last_sequence), (u32::MAX - 2, 19));
        assert_eq!((infos[1].whole, infos[1].cut, infos[1].missing), (false, false, 1));
        let counts = d.counts();
        assert_eq!((counts.frames, counts.whole, counts.cut, counts.late), (2, 0, 1, 1));
        assert!(d.last_whole().is_none());
        // Receiving stops partway through frame 3, while it is still arriving.
        d.push(0, &third[1], |_, _| panic!("not finished"));
        d.flush(Some(1_000_000), |info, _| infos.push(*info));
        assert_eq!((infos[2].whole, infos[2].cut, infos[2].packets), (false, true, 2));
        // The stream stopped partway through frame 4, long before receiving did.
        let fourth = packets(&f, &frame, 5400, 2000);
        d.push(0, &fourth[0], |_, _| panic!("not finished"));
        d.flush(Some(1_000_000_000), |info, _| infos.push(*info));
        assert_eq!((infos[3].whole, infos[3].cut), (false, false));
    }

    #[test]
    fn a_first_frame_that_starts_but_loses_packets_is_incomplete() {
        let f = format(320, 24);
        let frame = frame_of(&f);
        let one = packets(&f, &frame, 0, 0);
        let mut d = Depacketiser::new(&f).unwrap();
        let mut infos = Vec::new();
        for p in one.iter().take(2).chain(one.iter().skip(3)) {
            d.push(0, p, |info, _| infos.push(*info));
        }
        assert_eq!((infos[0].whole, infos[0].cut, infos[0].missing), (false, false, 1));
        assert_eq!(d.packets_per_frame(), None);
    }

    #[test]
    fn a_lost_first_packet_counts_as_missing_once_a_frame_came_whole() {
        let f = format(320, 24);
        let frame = frame_of(&f);
        let one = packets(&f, &frame, 0, 100);
        let two = packets(&f, &frame, 1800, 100 + one.len() as u32);
        let mut d = Depacketiser::new(&f).unwrap();
        let mut infos = Vec::new();
        for p in one.iter().chain(&two[1..]) {
            d.push(0, p, |info, _| infos.push(*info));
        }
        assert_eq!(infos.len(), 2);
        assert!(infos[0].whole);
        assert_eq!(d.packets_per_frame(), Some(24));
        assert_eq!((infos[1].whole, infos[1].missing), (false, 1));
    }

    #[test]
    fn overlapping_packets_leave_a_frame_short() {
        // A faulty sender writes packet 1's row header as packet 0's, so row 1 never comes.
        let f = format(320, 8);
        let frame = frame_of(&f);
        let mut all = packets(&f, &frame, 0, 0);
        let header = all[0][12 + 2..12 + 8].to_vec();
        all[1][12 + 2..12 + 8].copy_from_slice(&header);
        let mut d = Depacketiser::new(&f).unwrap();
        let mut got = Vec::new();
        for p in &all {
            d.push(0, p, |info, _| got.push(*info));
        }
        assert_eq!(got.len(), 1);
        assert!(!got[0].whole);
        assert_eq!(got[0].filled, f.frame_bytes() - f.row_bytes());
    }

    #[test]
    fn timestamps_that_step_back_start_a_new_frame() {
        // The sender's clock steps back a second between frames; its sequence numbers go on.
        let f = format(320, 24);
        let frame = frame_of(&f);
        let one = packets(&f, &frame, 900_000, 0);
        let two = packets(&f, &frame, 810_000, one.len() as u32);
        let three = packets(&f, &frame, 811_800, 2 * one.len() as u32);
        let mut d = Depacketiser::new(&f).unwrap();
        let mut infos = Vec::new();
        for p in one.iter().chain(&two).chain(&three) {
            d.push(0, p, |info, _| infos.push(*info));
        }
        assert_eq!(
            infos.iter().map(|i| (i.timestamp, i.whole)).collect::<Vec<_>>(),
            [(900_000, true), (810_000, true), (811_800, true)]
        );
        assert_eq!(d.counts().late, 0);
    }

    #[test]
    fn malformed_payload_headers_are_left_out() {
        let f = format(320, 24);
        let frame = frame_of(&f);
        let good = packets(&f, &frame, 0, 0);
        let mut d = Depacketiser::new(&f).unwrap();
        let mut bad = good[0].clone();
        bad[12 + 4] = 0x00;
        bad[12 + 5] = 24; // row 24 of 24
        d.push(0, &bad, |_, _| panic!("no frame"));
        let mut odd = good[0].clone();
        odd[12 + 3] = 0x01; // 1 octet: not a whole pixel group
        d.push(0, &odd, |_, _| panic!("no frame"));
        d.push(0, &good[0][..15], |_, _| panic!("no frame"));
        let mut field = good[0].clone();
        field[12 + 4] |= 0x80;
        d.push(0, &field, |_, _| panic!("no frame"));
        assert_eq!(d.counts().malformed, 4);
        assert_eq!(d.counts().packets, 0);
    }
}
