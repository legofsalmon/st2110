//! Payload checks: the sample row data headers and packing modes of ST 2110-20 video,
//! and the payload alignment VSF TR-08 asks of JPEG XS.

use st2110_sdp::Rule;
use st2110_sdp::video::{PixelGroup, Sampling, pixel_group};

use crate::report::Finding;
use crate::rtp::{SampleRow, SampleRows, sample_rows};
use crate::stats::Tally;
use crate::{Timeline, plural, rules};

/// Octets in a block of block packing mode (ST 2110-20:2022 §6.3.3).
const BLOCK: usize = 180;

/// IP datagrams shorter than this are to be avoided in general packing mode, except at
/// the end of a field or frame (ST 2110-20:2022 §6.3.2).
const SHORT: u32 = 1000;

/// Octets of the RFC 9134 payload header, before the JPEG XS payload data.
const JXSV_HEADER: u32 = 4;

/// What the SDP file says about a stream's payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PayloadConfig {
    /// The ST 2110-20 sampling and depth, as the SDP file spells them.
    pub sampling: Option<String>,
    pub depth: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Interlaced or PsF: rows count from 0 in each field or segment.
    pub fields: bool,
    /// The `PM` parameter.
    pub packing: Option<String>,
    /// Whether the encoding is JPEG XS (`jxsv`).
    pub jpeg_xs: bool,
}

/// The format the checks hold sample row data headers to.
#[derive(Clone, Copy, Debug)]
struct Raster {
    group: Option<PixelGroup>,
    /// Pixels a pixel group spans along a row: half its pixels for 4:2:0, which spans two rows.
    across: u32,
    width: Option<u32>,
    height: Option<u32>,
    fields: bool,
}

/// What a packet's place at the end of its field or frame decides.
#[derive(Clone, Copy, Debug)]
struct Held {
    t: i128,
    timestamp: u32,
    marker: bool,
    /// Octets of the IP datagram, under 1000 in general packing mode.
    short: Option<u32>,
    /// Octets of sample data that are not a multiple of 180, in block packing mode.
    unblocked: Option<usize>,
    /// Octets of JPEG XS payload data that are not a multiple of 8.
    unaligned: Option<u32>,
}

/// The last row segment of the packet before, to compare the next packet's with.
#[derive(Clone, Copy, Debug)]
struct Last {
    seq: u32,
    timestamp: u32,
    row: SampleRow,
}

/// One packet, as the payload checks see it.
pub(crate) struct Packet<'a> {
    pub t: i128,
    pub seq: u32,
    pub timestamp: u32,
    pub marker: bool,
    /// The start of the payload, holding the payload header.
    pub head: &'a [u8],
    /// Octets of payload, the RTP header and padding left out.
    pub payload_len: u32,
    /// Octets of the IP datagram.
    pub ip_length: u32,
}

pub(crate) struct PayloadChecks {
    raster: Option<Raster>,
    general: bool,
    block: bool,
    jpeg_xs: bool,
    held: Option<Held>,
    last: Option<Last>,
    /// Packets with any of the four faults below, and how many had each.
    malformed: Tally,
    not_groups: u64,
    empty: u64,
    too_many: u64,
    overrun: u64,
    disorder: Tally,
    outside: Tally,
    outside_at: Option<(u16, u16)>,
    short: Tally,
    unblocked: Tally,
    unaligned: Tally,
}

impl PayloadChecks {
    /// Checks for ST 2110-20 video when `raw`, else for compressed video.
    pub(crate) fn new(raw: bool, config: &PayloadConfig) -> Self {
        let raster = raw.then(|| {
            let sampling = config.sampling.as_deref().and_then(|s| s.parse::<Sampling>().ok());
            let depth = config.depth.as_deref().and_then(|d| d.parse().ok());
            let group = sampling.zip(depth).and_then(|(s, d)| pixel_group(s, d));
            let quarter = matches!(sampling, Some(Sampling::YCbCr420 | Sampling::ClYCbCr420 | Sampling::ICtCp420));
            let across = group.map_or(1, |g| if quarter { g.pixels / 2 } else { g.pixels });
            Raster { group, across, width: config.width, height: config.height, fields: config.fields }
        });
        let packing = config.packing.as_deref().map(str::to_ascii_uppercase);
        Self {
            raster,
            general: raw && packing.as_deref() == Some("2110GPM"),
            block: raw && packing.as_deref() == Some("2110BPM"),
            jpeg_xs: !raw && config.jpeg_xs,
            held: None,
            last: None,
            malformed: Tally::default(),
            not_groups: 0,
            empty: 0,
            too_many: 0,
            overrun: 0,
            disorder: Tally::default(),
            outside: Tally::default(),
            outside_at: None,
            short: Tally::default(),
            unblocked: Tally::default(),
            unaligned: Tally::default(),
        }
    }

    /// Takes the next packet in arrival order, once only.
    pub(crate) fn push(&mut self, p: &Packet<'_>) {
        if let Some(held) = self.held.take() {
            // A packet ends its field or frame when it has the marker bit, or the next
            // packet has another timestamp.
            if !held.marker && held.timestamp == p.timestamp {
                self.not_last(&held);
            }
        }
        let mut held = Held {
            t: p.t,
            timestamp: p.timestamp,
            marker: p.marker,
            short: (self.general && p.ip_length < SHORT).then_some(p.ip_length),
            unblocked: None,
            unaligned: None,
        };
        if self.jpeg_xs {
            let data = p.payload_len.saturating_sub(JXSV_HEADER);
            held.unaligned = (!data.is_multiple_of(8)).then_some(data);
        }
        if let Some(raster) = self.raster {
            let Some(rows) = sample_rows(p.head) else {
                self.last = None;
                self.held = Some(held);
                return;
            };
            let data: usize = rows.iter().map(|r| usize::from(r.length)).sum();
            if self.block && !data.is_multiple_of(BLOCK) {
                held.unblocked = Some(data);
            }
            self.sample_rows(p, raster, &rows, data);
        }
        self.held = Some(held);
    }

    fn not_last(&mut self, held: &Held) {
        if let Some(octets) = held.short {
            self.short.hit_min(held.t, f64::from(octets));
        }
        if let Some(octets) = held.unblocked {
            self.unblocked.hit_min(held.t, octets as f64);
        }
        if let Some(octets) = held.unaligned {
            self.unaligned.hit_min(held.t, f64::from(octets));
        }
    }

    fn sample_rows(&mut self, p: &Packet<'_>, raster: Raster, rows: &SampleRows, data: usize) {
        let count = rows.iter().count();
        let faults = [
            raster.group.is_some_and(|g| rows.iter().any(|r| u32::from(r.length) % g.octets != 0)),
            count > 1 && rows.iter().any(|r| r.length == 0),
            rows.more,
            (rows.header_length() + data) as u64 > u64::from(p.payload_len),
        ];
        if faults.contains(&true) {
            self.malformed.hit(p.t);
        }
        for (fault, n) in
            faults.into_iter().zip([&mut self.not_groups, &mut self.empty, &mut self.too_many, &mut self.overrun])
        {
            *n += u64::from(fault);
        }
        // A lone empty segment carries no samples, and has no place in the picture.
        if count == 1 && rows.rows[0].is_some_and(|r| r.length == 0) {
            return;
        }
        if let Some(r) = rows.iter().find(|r| !fits(&raster, r)) {
            self.outside.hit(p.t);
            self.outside_at.get_or_insert((r.row, r.offset));
        }
        let mut before = self
            .last
            .filter(|last| last.timestamp == p.timestamp && p.seq == last.seq.wrapping_add(1))
            .map(|last| last.row);
        let mut backwards = false;
        for r in rows.iter() {
            if let Some(b) = before
                && b.second_field == r.second_field
                && (r.row, r.offset) <= (b.row, b.offset)
            {
                backwards = true;
            }
            before = Some(r);
        }
        if backwards {
            self.disorder.hit(p.t);
        }
        self.last = before.map(|row| Last { seq: p.seq, timestamp: p.timestamp, row });
    }

    pub(crate) fn finish(&self, flow: usize, timeline: &Timeline, findings: &mut Vec<Finding>) {
        let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
            if tally.count > 0 {
                findings.push(Finding::new(rule, message, Some(flow), None, timeline.at(tally.first), tally.count));
            }
        };
        let octets = self.raster.and_then(|r| r.group).map_or(0, |g| g.octets);
        let wrong: Vec<String> = [
            (self.not_groups, format!("lengths that are not whole pixel groups of {octets} octets")),
            (self.empty, "an empty row segment beside others".to_string()),
            (self.too_many, "more than three row segments".to_string()),
            (self.overrun, "row segments that run past the end of the payload".to_string()),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} with {what}"))
        .collect();
        add(
            &rules::SRD_LENGTH,
            &self.malformed,
            format!(
                "{} had sample row data headers that ST 2110-20 does not allow: {}",
                plural(self.malformed.count, "packet"),
                wrong.join(", ")
            ),
        );
        add(
            &rules::SRD_ORDER,
            &self.disorder,
            format!(
                "{} started a row segment above, or to the left of, the one before it in the same field or frame",
                plural(self.disorder.count, "packet")
            ),
        );
        if let Some(raster) = self.raster {
            let (row, offset) = self.outside_at.unwrap_or_default();
            let size = match (raster.width, raster.height) {
                (Some(w), Some(h)) => format!("the {w}x{h} picture"),
                _ => "the picture".to_string(),
            };
            add(
                &rules::SRD_GEOMETRY,
                &self.outside,
                format!(
                    "{} placed samples outside {size} the SDP file gives, the first at row {row}, offset {offset}",
                    plural(self.outside.count, "packet")
                ),
            );
        }
        add(
            &rules::BPM_BLOCKS,
            &self.unblocked,
            format!(
                "{} other than the last of a field or frame carried sample data that is not a multiple of 180 octets, as few as {}",
                plural(self.unblocked.count, "packet"),
                self.unblocked.worst.unwrap_or_default()
            ),
        );
        add(
            &rules::GPM_SHORT,
            &self.short,
            format!(
                "{} other than the last of a field or frame were under 1000 octets, as few as {}",
                plural(self.short.count, "IP datagram"),
                self.short.worst.unwrap_or_default()
            ),
        );
        add(
            &rules::JXSV_ALIGNMENT,
            &self.unaligned,
            format!(
                "{} other than the last of a field or frame carried payload data that is not a multiple of 8 octets, as few as {}",
                plural(self.unaligned.count, "packet"),
                self.unaligned.worst.unwrap_or_default()
            ),
        );
    }
}

/// Whether a row segment lies within the picture: its row within the frame, or the
/// field (the first field has the odd row of an odd height), and its samples within the
/// width, rounded up to whole pixel groups.
fn fits(raster: &Raster, r: &SampleRow) -> bool {
    if let Some(height) = raster.height {
        let rows = match (raster.fields, r.second_field) {
            (false, _) => height,
            (true, false) => height.div_ceil(2),
            (true, true) => height / 2,
        };
        if u32::from(r.row) >= rows {
            return false;
        }
    }
    let (Some(width), Some(group)) = (raster.width, raster.group) else { return true };
    let across = raster.across.max(1);
    let end = u64::from(r.offset) + u64::from(r.length) / u64::from(group.octets) * u64::from(across);
    end <= u64::from(width.div_ceil(across) * across) && u32::from(r.offset) < width
}
