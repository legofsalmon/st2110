//! RP 2110-25 measurements of ST 2110-20 and ST 2110-22 video and ST 2110-40 ancillary
//! data, and the two ST 2110-21 timing models: the network compatibility model (CINST)
//! and the virtual receiver buffer (VRX).
//!
//! Times are integer nanoseconds on the analysis timeline, which is PTP time when the
//! capture's clock is known. Frame and read times that fall between nanoseconds are
//! compared exactly, in a finer unit, rather than rounded.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use st2110_sdp::{Rational, Rule};

use crate::report::{CinstReport, Finding, VideoReport, VideoWindow, VrxReport};
use crate::rtp::{AncField, VideoHeader};
use crate::rules;
use crate::stats::{Accumulator, NANOS, Seconds, Tally};
use crate::{Timeline, plural};

/// The RTP clock rate of video and ancillary data, in Hz.
const CLOCK: i128 = 90_000;

/// Arrivals held while the frame rate or NPACKETS is worked out, at most.
const HOLD_LIMIT: usize = 200_000;

/// Frame rates that a stream without an SDP file is taken to have, when its timestamps
/// step at one of them.
const STANDARD_RATES: [(u64, u64); 13] = [
    (24000, 1001),
    (24, 1),
    (25, 1),
    (30000, 1001),
    (30, 1),
    (48000, 1001),
    (48, 1),
    (50, 1),
    (60000, 1001),
    (60, 1),
    (100, 1),
    (120000, 1001),
    (120, 1),
];

/// Which part of ST 2110 the stream follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VideoKind {
    /// ST 2110-20.
    Uncompressed,
    /// ST 2110-22.
    Compressed,
    /// ST 2110-40.
    Ancillary,
}

/// An ST 2110-21 sender type, from the SDP file's `TP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SenderType {
    /// `2110TPN`: narrow, gapped.
    Narrow,
    /// `2110TPNL`: narrow, linear.
    NarrowLinear,
    /// `2110TPW`: wide.
    Wide,
}

impl SenderType {
    pub(crate) fn parse(tp: &str) -> Option<Self> {
        match tp.trim().to_ascii_uppercase().as_str() {
            "2110TPN" => Some(Self::Narrow),
            "2110TPNL" => Some(Self::NarrowLinear),
            "2110TPW" => Some(Self::Wide),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Narrow => "2110TPN",
            Self::NarrowLinear => "2110TPNL",
            Self::Wide => "2110TPW",
        }
    }
}

/// What the SDP file says about the stream, where there is one.
#[derive(Clone, Debug, Default)]
pub(crate) struct VideoConfig {
    pub frame_rate: Option<Rational>,
    /// `None` when unknown: then the payload headers' field bits decide.
    pub interlaced: Option<bool>,
    pub segmented: bool,
    pub height: Option<u32>,
    pub sender: Option<SenderType>,
    pub troff_us: Option<u32>,
    pub cmax: Option<u32>,
    pub maxudp: Option<u32>,
}

/// One packet, as the timing measurements see it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Arrival {
    pub t: i128,
    /// The sequence number, extended to 32 bits where the payload header carries the
    /// high bits.
    pub seq: u32,
    pub timestamp: u32,
    pub marker: bool,
    pub video: Option<VideoHeader>,
    pub anc: Option<AncField>,
}

impl Arrival {
    fn second_field(&self) -> bool {
        self.video.is_some_and(|v| v.second_field) || self.anc == Some(AncField::Second)
    }

    /// Whether the payload header shows the packet starts a frame: its first row
    /// segment is row 0 of the first field, from the left edge.
    fn starts_frame(&self) -> bool {
        self.video.is_some_and(|v| v.row == 0 && v.offset == 0 && !v.second_field)
    }
}

/// Packets with one RTP timestamp: a frame, or a field of interlaced video.
#[derive(Clone, Copy, Debug)]
struct Unit {
    timestamp: u32,
    last_t: i128,
    last_seq: u32,
    packets: u32,
    /// Whether packets are missing from it.
    gaps: bool,
    second_field: bool,
}

/// The frame in progress, which reads its packets on one schedule.
#[derive(Clone, Copy, Debug)]
struct Frame {
    tpa0: i128,
    first_seq: Option<u32>,
    /// Whether every packet so far arrived, with the first one known.
    whole: bool,
}

/// An arrival as the timing models need it.
#[derive(Clone, Copy, Debug)]
struct ModelArrival {
    t: i128,
    /// The first packet's arrival and this packet's index in its frame, when known.
    slot: Option<(i128, u32)>,
}

#[derive(Default)]
struct Window {
    fpt: Accumulator,
    rtp_offset: Accumulator,
    latency: Accumulator,
    gap: Accumulator,
}

pub(crate) struct VideoEngine {
    kind: VideoKind,
    config: VideoConfig,
    /// Whether times are PTP time, which the absolute measurements need.
    absolute: bool,
    rate: Option<Rational>,
    /// Arrivals held while the frame rate is worked out, and how many timestamps they
    /// have between them.
    held: Vec<Arrival>,
    held_timestamps: usize,
    inferring: bool,
    /// The highest row number that payload headers have named.
    max_row: Option<u16>,
    saw_second_field: bool,
    /// Whether the two fields' packets have shared a timestamp, as PsF segments do.
    fields_share_timestamp: bool,
    unit: Option<Unit>,
    closed: Option<u32>,
    last: Option<Arrival>,
    frame: Option<Frame>,
    npackets: Option<u32>,
    held_models: Vec<ModelArrival>,
    models_off: Option<&'static str>,
    cinst: Option<Cinst>,
    vrx: Option<Vrx>,
    units: u64,
    fpt: Accumulator,
    rtp_offset: Accumulator,
    latency: Accumulator,
    gap: Accumulator,
    frame_packets: Accumulator,
    windows: Seconds<Window>,
    marker_missing: Tally,
    marker_extra: Tally,
    misaligned: Tally,
    future: Tally,
    late: Tally,
    packets_vary: Tally,
}

/// The largest frame rate numerator and denominator, and NPACKETS, that the timing and
/// models take: far past any format, and small enough that their products cannot overflow.
const RANGE: u64 = 1_000_000;

impl VideoEngine {
    pub(crate) fn new(kind: VideoKind, config: VideoConfig, absolute: bool) -> Self {
        let rate = config.frame_rate.filter(|r| r.numerator() <= RANGE && r.denominator() <= RANGE);
        let models_off = (rate != config.frame_rate).then_some("the SDP file's frame rate is out of range");
        Self {
            kind,
            rate,
            inferring: config.frame_rate.is_none(),
            config,
            absolute,
            held: Vec::new(),
            held_timestamps: 0,
            max_row: None,
            saw_second_field: false,
            fields_share_timestamp: false,
            unit: None,
            closed: None,
            last: None,
            frame: None,
            npackets: None,
            held_models: Vec::new(),
            models_off,
            cinst: None,
            vrx: None,
            units: 0,
            fpt: Accumulator::default(),
            rtp_offset: Accumulator::default(),
            latency: Accumulator::default(),
            gap: Accumulator::default(),
            frame_packets: Accumulator::default(),
            windows: Seconds::default(),
            marker_missing: Tally::default(),
            marker_extra: Tally::default(),
            misaligned: Tally::default(),
            future: Tally::default(),
            late: Tally::default(),
            packets_vary: Tally::default(),
        }
    }

    /// Takes the next packet, in arrival order.
    pub(crate) fn push(&mut self, a: Arrival) {
        if a.second_field() {
            self.saw_second_field = true;
        }
        if let Some(v) = a.video {
            self.max_row = self.max_row.max(Some(v.row));
        }
        if self.inferring {
            if self.held.last().is_none_or(|last| last.timestamp != a.timestamp) {
                self.held_timestamps += 1;
            }
            self.held.push(a);
            if self.held_timestamps >= 12 || self.held.len() >= HOLD_LIMIT {
                self.infer_rate();
            }
            return;
        }
        self.process(a);
    }

    /// Whether the video is interlaced: from the SDP file, or else from the field bits.
    fn interlaced(&self) -> bool {
        self.config.interlaced.unwrap_or(self.saw_second_field)
    }

    fn segmented(&self) -> bool {
        self.config.segmented || (self.config.interlaced.is_none() && self.fields_share_timestamp)
    }

    /// Whether each field carries its own timestamp, so that a unit is a field.
    fn field_units(&self) -> bool {
        self.interlaced() && !self.segmented() && self.kind != VideoKind::Compressed
    }

    /// Works out the frame rate from the held timestamps, then measures the held packets.
    fn infer_rate(&mut self) {
        self.inferring = false;
        let mut stamps: Vec<u32> = Vec::new();
        // Whether the run of packets with the latest timestamp has had first-field and
        // second-field packets: both, in ST 2110-20 video, make PsF.
        let (mut first, mut second) = (false, false);
        for a in &self.held {
            if stamps.last() != Some(&a.timestamp) {
                stamps.push(a.timestamp);
                (first, second) = (false, false);
            }
            if a.second_field() {
                second = true;
            } else {
                first = true;
            }
            if first && second && self.kind == VideoKind::Uncompressed {
                self.fields_share_timestamp = true;
            }
        }
        let per_frame = if self.field_units() { 2 } else { 1 };
        self.rate = frame_rate_from(&stamps, per_frame);
        for a in std::mem::take(&mut self.held) {
            self.process(a);
        }
    }

    fn checks_marker(&self) -> bool {
        self.kind != VideoKind::Compressed && !self.segmented()
    }

    fn process(&mut self, a: Arrival) {
        match self.unit {
            Some(unit) if unit.timestamp == a.timestamp => {
                if let Some(last) = self.last
                    && last.marker
                    && last.timestamp == a.timestamp
                    && a.seq == last.seq.wrapping_add(1)
                    && self.checks_marker()
                {
                    self.marker_extra.hit(a.t);
                }
                if a.second_field() != unit.second_field && self.kind == VideoKind::Uncompressed {
                    self.fields_share_timestamp = true;
                }
                let unit = self.unit.as_mut().expect("matched above");
                unit.packets += 1;
                unit.last_t = a.t;
                if a.seq != unit.last_seq.wrapping_add(1) {
                    unit.gaps = true;
                    if let Some(frame) = &mut self.frame {
                        frame.whole = false;
                    }
                }
                if seq_after(a.seq, unit.last_seq) {
                    unit.last_seq = a.seq;
                }
                self.model(&a);
            }
            _ if self.closed == Some(a.timestamp) => {
                // A straggler from the unit before: it fills the buffers, but it has no
                // place in the read schedule of the frame in progress.
                if let Some(cinst) = &mut self.cinst {
                    cinst.arrive(a.t);
                } else if self.models_off.is_none() {
                    self.hold_model(ModelArrival { t: a.t, slot: None });
                }
            }
            _ => self.start_unit(a),
        }
        self.last = Some(a);
    }

    fn start_unit(&mut self, a: Arrival) {
        let previous = self.unit.take();
        if let Some(unit) = previous {
            self.close_unit(unit, &a);
            self.closed = Some(unit.timestamp);
            if let Some(last) = self.last
                && last.timestamp == unit.timestamp
                && a.seq == last.seq.wrapping_add(1)
                && !last.marker
                && self.checks_marker()
            {
                self.marker_missing.hit(last.t);
            }
            let gap = (a.t - unit.last_t) as f64 / 1000.0;
            self.gap.add(gap);
            self.windows.at(a.t).gap.add(gap);
        }
        let second_field = self.field_units() && a.second_field();
        let first_seq = match self.last {
            Some(last) if a.seq == last.seq.wrapping_add(1) => Some(a.seq),
            Some(last) if last.marker && seq_after(a.seq, last.seq) => Some(last.seq.wrapping_add(1)),
            _ if a.starts_frame() => Some(a.seq),
            _ => None,
        };
        let continues_frame = second_field && previous.is_some_and(|u| !u.second_field);
        self.frame = if !second_field {
            Some(Frame { tpa0: a.t, first_seq, whole: first_seq == Some(a.seq) })
        } else if continues_frame {
            self.frame.map(|f| Frame { whole: f.whole && first_seq == Some(a.seq), ..f })
        } else {
            None
        };
        self.unit = Some(Unit {
            timestamp: a.timestamp,
            last_t: a.t,
            last_seq: a.seq,
            packets: 1,
            gaps: first_seq != Some(a.seq),
            second_field,
        });
        self.units += 1;
        self.measure(&a, !second_field);
        self.model(&a);
    }

    /// Accounts for a unit that `next` has just followed.
    fn close_unit(&mut self, unit: Unit, next: &Arrival) {
        let whole = !unit.gaps && next.seq == unit.last_seq.wrapping_add(1);
        if self.kind == VideoKind::Ancillary {
            return;
        }
        let Some(frame) = self.frame.filter(|f| f.whole && whole) else { return };
        // The frame ends with this unit unless it is the first field of two.
        if self.field_units() && !unit.second_field {
            return;
        }
        let Some(first) = frame.first_seq else { return };
        let packets = unit.last_seq.wrapping_sub(first).saturating_add(1);
        self.frame_packets.add(f64::from(packets));
        match self.npackets {
            None => {
                self.npackets = Some(packets);
                self.start_models();
            }
            Some(n) if n != packets && self.kind == VideoKind::Compressed => {
                self.packets_vary.hit_max(next.t, f64::from(packets));
            }
            Some(_) => {}
        }
    }

    /// FPT, RTP offset and latency at the first packet of a unit (RP 2110-25 §4.8).
    fn measure(&mut self, a: &Arrival, starts_frame: bool) {
        if !self.absolute {
            return;
        }
        let t = a.t;
        let ts = unwrap(a.timestamp, t, CLOCK);
        let latency = (t * CLOCK - ts * NANOS) as f64 / CLOCK as f64 / 1000.0;
        self.latency.add(latency);
        self.windows.at(t).latency.add(latency);
        let limit = if self.kind == VideoKind::Ancillary { 35_000.0 } else { 1_000.0 };
        if latency < 0.0 {
            self.future.hit_min(t, latency);
        } else if latency > limit {
            self.late.hit_max(t, latency);
        }
        let Some(rate) = self.rate else { return };
        let (num, den) = (i128::from(rate.numerator()), i128::from(rate.denominator()));
        let per_frame = if self.field_units() { 2 } else { 1 };
        let k = round_div(ts * num * per_frame, den * CLOCK);
        let grid = (k * den * CLOCK).div_euclid(num * per_frame);
        if grid != ts {
            self.misaligned.hit_max(t, (ts - grid).abs() as f64);
        }
        if starts_frame {
            // The frame reference nearest the first packet: TCF = N × TFRAME.
            let n = round_div(t * num, den * NANOS);
            let fpt = (t * num - n * den * NANOS) as f64 / num as f64 / 1000.0;
            let offset = (ts - (n * den * CLOCK).div_euclid(num)) as f64;
            self.fpt.add(fpt);
            self.rtp_offset.add(offset);
            let window = self.windows.at(t);
            window.fpt.add(fpt);
            window.rtp_offset.add(offset);
        }
    }

    fn model(&mut self, a: &Arrival) {
        if self.kind == VideoKind::Ancillary || self.models_off.is_some() {
            return;
        }
        let slot = self.frame.and_then(|f| {
            let j = a.seq.wrapping_sub(f.first_seq?);
            (j < 1 << 24).then_some((f.tpa0, j))
        });
        let m = ModelArrival { t: a.t, slot };
        if self.cinst.is_some() {
            self.run_models(m);
        } else {
            self.hold_model(m);
        }
    }

    fn hold_model(&mut self, m: ModelArrival) {
        if self.held_models.len() < HOLD_LIMIT {
            self.held_models.push(m);
        } else {
            self.held_models = Vec::new();
            self.models_off = Some("no whole frame arrived to count NPACKETS from");
        }
    }

    fn run_models(&mut self, m: ModelArrival) {
        if let Some(cinst) = &mut self.cinst {
            cinst.arrive(m.t);
        }
        if let (Some(vrx), Some((tpa0, j))) = (&mut self.vrx, m.slot) {
            vrx.arrive(m.t, tpa0, j);
        }
    }

    fn start_models(&mut self) {
        if self.models_off.is_some() {
            return;
        }
        let (Some(rate), Some(np)) = (self.rate, self.npackets) else {
            self.models_off = Some("the frame rate is unknown");
            return;
        };
        if u64::from(np) > RANGE {
            self.models_off = Some("NPACKETS is out of range");
            return;
        }
        let signalled = self.config.cmax;
        let cmax = Cmax::new(rate, np, self.raster().active);
        let limit = signalled.or(match self.config.sender {
            Some(SenderType::Narrow) => Some(cmax.narrow),
            Some(SenderType::NarrowLinear) => Some(cmax.narrow_linear),
            Some(SenderType::Wide) => cmax.wide,
            None => None,
        });
        // The level CINST fails over: the CMAX that applies; without a sender type, every
        // type's; and none for a wide sender at a rate with no wide CMAX.
        let judge = match (limit, self.config.sender) {
            (Some(limit), _) => Some(limit),
            (None, None) => Some(cmax.widest()),
            (None, Some(_)) => None,
        };
        self.cinst = Some(Cinst::new(rate, np, cmax, limit, judge));
        if self.kind == VideoKind::Uncompressed && self.absolute {
            self.vrx = self.config.sender.map(|sender| {
                let raster = self.raster();
                let fields = self.interlaced() || self.segmented();
                Vrx::new(rate, np, sender, raster, fields, self.config.troff_us, self.config.maxudp)
            });
        }
        for m in std::mem::take(&mut self.held_models) {
            self.run_models(m);
        }
    }

    fn raster(&self) -> Raster {
        Raster::new(self.interlaced() || self.segmented(), self.height())
    }

    /// The image height: from the SDP file, or else from the rows the payload headers
    /// name, which count each field's rows on their own.
    fn height(&self) -> Option<u32> {
        let fields = if self.interlaced() || self.segmented() { 2 } else { 1 };
        self.config.height.or_else(|| self.max_row.map(|row| (u32::from(row) + 1) * fields))
    }

    pub(crate) fn finish(mut self, flow: usize, timeline: &Timeline) -> (VideoReport, Vec<Finding>) {
        if self.inferring {
            self.infer_rate();
        }
        if self.cinst.is_none() && self.models_off.is_none() && self.kind != VideoKind::Ancillary {
            self.models_off = Some(match (self.rate, self.npackets) {
                (None, _) => "the frame rate is unknown",
                (_, None) => "no whole frame arrived to count NPACKETS from",
                _ => "the models did not start",
            });
        }
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
            if tally.count > 0 {
                findings.push(Finding::new(rule, message, Some(flow), None, timeline.at(tally.first), tally.count));
            }
        };
        let unit_word = if self.field_units() { "field" } else { "frame" };
        add(
            &rules::MARKER_BIT,
            &self.marker_missing,
            format!("the last packet of {} had no marker bit set", plural(self.marker_missing.count, unit_word)),
        );
        add(
            &rules::MARKER_BIT,
            &self.marker_extra,
            format!(
                "{} had the marker bit set but more packets of the same {unit_word} followed",
                plural(self.marker_extra.count, "packet")
            ),
        );
        add(
            &rules::RTP_ALIGNMENT,
            &self.misaligned,
            format!(
                "{} of {} timestamps were off the {unit_word} boundaries that ST 2059-1 counts from the SMPTE Epoch, by up to {} ticks at 90 kHz",
                self.misaligned.count,
                self.units,
                self.misaligned.worst.unwrap_or_default()
            ),
        );
        add(
            &rules::TIMESTAMP_FUTURE,
            &self.future,
            format!(
                "{} arrived before the time its RTP timestamp names, by up to {:.1} µs: the sender's clock, or the capture's, runs ahead of PTP time",
                plural(self.future.count, unit_word),
                -self.future.worst.unwrap_or_default()
            ),
        );
        let limit = if self.kind == VideoKind::Ancillary { "35 ms" } else { "1 ms" };
        add(
            &rules::TIMESTAMP_LATE,
            &self.late,
            format!(
                "latency from RTP timestamp to first packet reached {:.1} µs, over {limit}, in {}; a sender that preserves upstream timestamps (TSMODE=SAMP) shows its processing delay here",
                self.late.worst.unwrap_or_default(),
                plural(self.late.count, unit_word)
            ),
        );
        add(
            &rules::FRAME_PACKETS,
            &self.packets_vary,
            format!(
                "frames carried from {} to {} packets",
                self.frame_packets.stats().map_or(0.0, |s| s.min),
                self.frame_packets.stats().map_or(0.0, |s| s.max)
            ),
        );
        let cinst = self.cinst.as_ref().map(|c| {
            let sender = match (self.config.cmax, self.config.sender) {
                (Some(_), _) => "the CMAX the SDP file signals".to_string(),
                (None, Some(sender)) => format!("sender type {}", sender.name()),
                (None, None) => "every sender type".to_string(),
            };
            if let Some(cmax) = c.judge
                && c.exceeded.count > 0
            {
                findings.push(Finding::new(
                    &rules::CINST,
                    format!(
                        "CINST reached {}, over CMAX {cmax} for {sender}, on {}",
                        c.peak,
                        plural(c.exceeded.count, "packet")
                    ),
                    Some(flow),
                    None,
                    timeline.at(c.exceeded.first),
                    c.exceeded.count,
                ));
            }
            c.report(self.config.sender, self.config.cmax)
        });
        let vrx = self.vrx.as_ref().map(|v| {
            if v.overflow.count > 0 {
                findings.push(Finding::new(
                    &rules::VRX_OVERFLOW,
                    format!(
                        "the buffer held up to {} packets, over VRXFULL {}, after {}",
                        v.peak,
                        v.vrxfull,
                        plural(v.overflow.count, "arrival")
                    ),
                    Some(flow),
                    None,
                    timeline.at(v.overflow.first),
                    v.overflow.count,
                ));
            }
            if v.underflow.count > 0 {
                findings.push(Finding::new(
                    &rules::VRX_UNDERFLOW,
                    format!(
                        "{} arrived after its read time, the latest by {:.1} µs",
                        plural(v.underflow.count, "packet"),
                        v.underflow.worst.unwrap_or_default()
                    ),
                    Some(flow),
                    None,
                    timeline.at(v.underflow.first),
                    v.underflow.count,
                ));
            }
            v.report()
        });
        let vrx_off = match (&self.vrx, self.kind) {
            (Some(_), _) | (None, VideoKind::Ancillary | VideoKind::Compressed) => None,
            (None, VideoKind::Uncompressed) => Some(if let Some(why) = self.models_off {
                why
            } else if !self.absolute {
                "the capture's clock is not on PTP time"
            } else {
                "the SDP file gives no TP, so the read schedule is unknown"
            }),
        };
        let (height, interlaced, segmented) = (self.height(), self.interlaced(), self.segmented());
        let mut windows: Vec<VideoWindow> = std::mem::take(&mut self.windows)
            .finish()
            .into_iter()
            .map(|(second, w)| VideoWindow {
                second,
                fpt: w.fpt.stats(),
                rtp_offset: w.rtp_offset.stats(),
                latency: w.latency.stats(),
                gap: w.gap.stats(),
                cinst: None,
                vrx: None,
            })
            .collect();
        if let Some(c) = self.cinst {
            merge(&mut windows, c.seconds.finish(), |w, peak| w.cinst = Some(peak));
        }
        if let Some(v) = self.vrx {
            merge(&mut windows, v.seconds.finish(), |w, peak| w.vrx = Some(peak));
        }
        let report = VideoReport {
            frame_rate: self.rate.map(|r| r.to_string()),
            height,
            interlaced,
            segmented,
            units: self.units,
            packets_per_frame: self.frame_packets.stats(),
            npackets: self.npackets,
            fpt: self.fpt.stats(),
            rtp_offset: self.rtp_offset.stats(),
            latency: self.latency.stats(),
            gap: self.gap.stats(),
            cinst,
            vrx,
            models_skipped: self.models_off.filter(|_| self.kind != VideoKind::Ancillary).map(str::to_string),
            vrx_skipped: vrx_off.map(str::to_string),
            windows,
        };
        (report, findings)
    }
}

/// Fills in each window's value from a per-second series, adding windows it lacks.
fn merge(windows: &mut Vec<VideoWindow>, series: Vec<(i64, u64)>, set: impl Fn(&mut VideoWindow, u64)) {
    for (second, value) in series {
        match windows.binary_search_by_key(&second, |w| w.second) {
            Ok(i) => set(&mut windows[i], value),
            Err(i) => {
                let mut window = VideoWindow {
                    second,
                    fpt: None,
                    rtp_offset: None,
                    latency: None,
                    gap: None,
                    cinst: None,
                    vrx: None,
                };
                set(&mut window, value);
                windows.insert(i, window);
            }
        }
    }
}

/// Whether sequence number `a` comes after `b`, allowing for wrap-around.
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// `num ÷ den` rounded to the nearest integer, halves away from zero, as RP 2110-25
/// §4.3 rounds. `den` is positive.
pub(crate) fn round_div(num: i128, den: i128) -> i128 {
    let q = (2 * num.abs() + den) / (2 * den);
    if num < 0 { -q } else { q }
}

/// A timestamp as a tick count since the epoch: of the counts it could stand for, 2³²
/// ticks apart, the one nearest the count at `t` nanoseconds.
pub(crate) fn unwrap(timestamp: u32, t: i128, clock: i128) -> i128 {
    let now = (t * clock).div_euclid(NANOS);
    now + i128::from(timestamp.wrapping_sub(now as u32) as i32)
}

/// The frame rate that timestamps stepping from one unit to the next give, when it is
/// one of the standard rates. `per_frame` is 2 when each field has its own timestamp.
fn frame_rate_from(stamps: &[u32], per_frame: u64) -> Option<Rational> {
    let mut steps: Vec<u32> =
        stamps.windows(2).map(|w| w[1].wrapping_sub(w[0])).filter(|&s| s > 0 && s < 1 << 20).collect();
    if steps.is_empty() {
        return None;
    }
    steps.sort_unstable();
    let median = steps[steps.len() / 2];
    let kept: Vec<u64> = steps.iter().filter(|&&s| s.abs_diff(median) <= 1).map(|&s| u64::from(s)).collect();
    let (count, ticks) = (kept.len() as u64, kept.iter().sum::<u64>());
    // Units per second: 90 000 × count ÷ ticks; frames per second: that ÷ per_frame.
    STANDARD_RATES.iter().find_map(|&(num, den)| {
        // Compare 90 000 × count × den with num × per_frame × ticks, within 0.1%.
        let measured = 90_000 * u128::from(count) * u128::from(den);
        let standard = u128::from(num) * u128::from(per_frame) * u128::from(ticks);
        (measured.abs_diff(standard) * 1000 <= standard).then(|| Rational::new(num, den)).flatten()
    })
}

/// The active raster and default read offset for a format (ST 2110-21:2022 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Raster {
    /// RACTIVE as a fraction.
    active: (i128, i128),
    /// TRODEFAULT as a fraction of TFRAME.
    offset: (i128, i128),
}

impl Raster {
    fn new(fields: bool, height: Option<u32>) -> Self {
        if !fields {
            let offset = if height.is_none_or(|h| h >= 1080) { (43, 1125) } else { (28, 750) };
            return Self { active: (1080, 1125), offset };
        }
        // The legacy ST 2110-21:2017 values for 525, 625 and 1125 lines, which ST 2110-21:2022
        // Table 1 is meant to keep.
        let lines = match height {
            Some(h) if h <= 487 => 525,
            Some(h) if h <= 576 => 625,
            _ => 1125,
        };
        match lines {
            525 => Self { active: (487, 525), offset: (20, 525) },
            625 => Self { active: (576, 625), offset: (26, 625) },
            _ => Self { active: (1080, 1125), offset: (22, 1125) },
        }
    }
}

/// CMAX for each sender type (ST 2110-21:2022 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cmax {
    narrow: u32,
    narrow_linear: u32,
    /// `None` at 900 000 packets a second and more, where the formula does not apply.
    wide: Option<u32>,
}

impl Cmax {
    fn new(rate: Rational, np: u32, active: (i128, i128)) -> Self {
        let (num, den, np) = (i128::from(rate.numerator()), i128::from(rate.denominator()), i128::from(np));
        let packets_per_second = np * num / den;
        let floor = |n: i128, d: i128| u32::try_from(n / d).unwrap_or(u32::MAX);
        Self {
            narrow: floor(np * num * active.1, 43_200 * den * active.0).max(4),
            narrow_linear: floor(np * num, 43_200 * den).max(4),
            wide: (packets_per_second < 900_000).then(|| floor(np * num, 21_600 * den).max(16)),
        }
    }

    /// The largest of the three: without a sender type, only a level over it fails.
    fn widest(&self) -> u32 {
        self.wide.unwrap_or(0).max(self.narrow).max(self.narrow_linear)
    }
}

/// The network compatibility model: a bucket drained one packet every TDRAIN at
/// instants counted from the SMPTE Epoch (ST 2110-21:2022 §6.6.1).
struct Cinst {
    /// TDRAIN is `drain.1 ÷ drain.0` nanoseconds.
    drain: (i128, i128),
    last_drain: Option<i128>,
    level: u64,
    peak: u64,
    cmax: Cmax,
    /// The CMAX that applies: signalled, or the sender type's.
    limit: Option<u32>,
    /// The CMAX that a level over fails.
    judge: Option<u32>,
    exceeded: Tally,
    seconds: Seconds<u64>,
}

impl Cinst {
    fn new(rate: Rational, np: u32, cmax: Cmax, limit: Option<u32>, judge: Option<u32>) -> Self {
        let (num, den) = (i128::from(rate.numerator()), i128::from(rate.denominator()));
        // TDRAIN = TFRAME ÷ (NPACKETS × 1.1) = 10 × den × 10⁹ ÷ (11 × num × NPACKETS) ns.
        Self {
            drain: (11 * num * i128::from(np), 10 * den * NANOS),
            last_drain: None,
            level: 0,
            peak: 0,
            cmax,
            limit,
            judge,
            exceeded: Tally::default(),
            seconds: Seconds::default(),
        }
    }

    fn arrive(&mut self, t: i128) {
        let k = (t * self.drain.0).div_euclid(self.drain.1);
        if let Some(last) = self.last_drain {
            self.level = self.level.saturating_sub(u64::try_from(k - last).unwrap_or(0));
        }
        self.last_drain = Some(self.last_drain.map_or(k, |last| last.max(k)));
        self.level += 1;
        self.peak = self.peak.max(self.level);
        let second = self.seconds.at(t);
        *second = (*second).max(self.level);
        if let Some(judge) = self.judge
            && self.level > u64::from(judge)
        {
            self.exceeded.hit_max(t, self.level as f64);
        }
    }

    fn report(&self, sender: Option<SenderType>, signalled: Option<u32>) -> CinstReport {
        let peak = self.peak;
        let fits = |cmax: u32| peak <= u64::from(cmax);
        let mut types = Vec::new();
        if fits(self.cmax.narrow) {
            types.push("2110TPN".to_string());
        }
        if fits(self.cmax.narrow_linear) {
            types.push("2110TPNL".to_string());
        }
        if self.cmax.wide.is_some_and(fits) {
            types.push("2110TPW".to_string());
        }
        CinstReport {
            peak,
            sender_type: sender.map(|s| s.name().to_string()),
            cmax: self.limit,
            signalled_cmax: signalled,
            cmax_narrow: self.cmax.narrow,
            cmax_narrow_linear: self.cmax.narrow_linear,
            cmax_wide: self.cmax.wide,
            fits: types,
            drain_us: self.drain.1 as f64 / self.drain.0 as f64 / 1000.0,
        }
    }
}

/// Read times in units of `1 ÷ scale` nanoseconds, so that every term is an integer.
#[derive(Clone, Copy, Debug)]
struct Schedule {
    scale: i128,
    frame: i128,
    offset: i128,
    step: i128,
    half: i128,
    np: i128,
    /// Whether the second half of the packets is read half a frame later: the gapped
    /// schedule of interlaced and PsF video.
    fields: bool,
}

impl Schedule {
    fn new(rate: Rational, np: u32, gapped: bool, raster: Raster, fields: bool, troff_us: Option<u32>) -> Self {
        let (num, den, np) = (i128::from(rate.numerator()), i128::from(rate.denominator()), i128::from(np));
        let (ra, rd) = raster.active;
        let tro_den = if troff_us.is_some() { 1 } else { raster.offset.1 };
        let b = lcm(rd, tro_den);
        let scale = num * b * np * 2;
        // TFRAME = den × 10⁹ ÷ num ns.
        let frame = den * NANOS * b * np * 2;
        let step = if gapped { den * NANOS * ra * (b / rd) * 2 } else { den * NANOS * b * 2 };
        let offset = match troff_us {
            Some(us) => i128::from(us) * 1000 * scale,
            None => raster.offset.0 * den * NANOS * (b / raster.offset.1) * np * 2,
        };
        Self { scale, frame, offset, step, half: frame / 2, np, fields: fields && gapped }
    }

    /// Read time of packet `j` of frame `n`: TPR0 + j × TRS, with the second field read
    /// from TPR0 + TFRAME ÷ 2 (ST 2110-21:2022 §6.3.3, without the TLINE ÷ 2 term that
    /// would move the RTP timestamp).
    fn read(&self, n: i128, j: i128) -> i128 {
        let start = n * self.frame + self.offset;
        if self.fields && 2 * j >= self.np {
            start + self.half + (2 * j - self.np) * self.step / 2
        } else {
            start + j * self.step
        }
    }

    /// The transmission slot nearest a frame whose first packet arrived at `tpa0`: the
    /// N for which N × TFRAME + TROFFSET is closest.
    fn frame_index(&self, tpa0: i128) -> i128 {
        round_div(tpa0 * self.scale - self.offset, self.frame)
    }
}

fn lcm(a: i128, b: i128) -> i128 {
    let (mut x, mut y) = (a, b);
    while y != 0 {
        (x, y) = (y, x % y);
    }
    a / x * b
}

/// The virtual receiver buffer, by event history with each packet read at its own read
/// time (ST 2110-21:2022 §6.6.2; RP 2110-25:2023 Annex A).
struct Vrx {
    schedule: Schedule,
    gapped: bool,
    troff_us: f64,
    signalled: bool,
    vrxfull: u64,
    /// Read times of the packets in the buffer.
    buffer: BinaryHeap<Reverse<i128>>,
    peak: u64,
    margin: Accumulator,
    underflow: Tally,
    overflow: Tally,
    seconds: Seconds<u64>,
}

impl Vrx {
    fn new(
        rate: Rational,
        np: u32,
        sender: SenderType,
        raster: Raster,
        fields: bool,
        troff_us: Option<u32>,
        maxudp: Option<u32>,
    ) -> Self {
        let gapped = sender == SenderType::Narrow;
        let schedule = Schedule::new(rate, np, gapped, raster, fields, troff_us);
        let (num, den, np) = (i128::from(rate.numerator()), i128::from(rate.denominator()), i128::from(np));
        // ST 2110-21 takes MAXUDP as 1500 when the standard UDP size limit applies.
        let maxudp = i128::from(maxudp.unwrap_or(1500).max(1));
        let vrxfull = match sender {
            SenderType::Wide => (1500 * 720 / maxudp).max(np * num / (300 * den)),
            _ => (1500 * 8 / maxudp).max(np * num / (27_000 * den)),
        };
        let offset_ns = schedule.offset as f64 / schedule.scale as f64;
        Self {
            schedule,
            gapped,
            troff_us: offset_ns / 1000.0,
            signalled: troff_us.is_some(),
            vrxfull: u64::try_from(vrxfull).unwrap_or(u64::MAX),
            buffer: BinaryHeap::new(),
            peak: 0,
            margin: Accumulator::default(),
            underflow: Tally::default(),
            overflow: Tally::default(),
            seconds: Seconds::default(),
        }
    }

    fn arrive(&mut self, t: i128, tpa0: i128, j: u32) {
        let now = t * self.schedule.scale;
        while self.buffer.peek().is_some_and(|Reverse(read)| *read < now) {
            self.buffer.pop();
        }
        let n = self.schedule.frame_index(tpa0);
        let read = self.schedule.read(n, i128::from(j));
        let margin = (read - now) as f64 / self.schedule.scale as f64 / 1000.0;
        self.margin.add(margin);
        if read < now {
            self.underflow.hit_max(t, -margin);
            return;
        }
        self.buffer.push(Reverse(read));
        let level = self.buffer.len() as u64;
        self.peak = self.peak.max(level);
        let second = self.seconds.at(t);
        *second = (*second).max(level);
        if level > self.vrxfull {
            self.overflow.hit_max(t, level as f64);
        }
    }

    fn report(&self) -> VrxReport {
        VrxReport {
            schedule: if self.gapped { "gapped" } else { "linear" }.to_string(),
            troffset_us: self.troff_us,
            troffset_signalled: self.signalled,
            vrxfull: self.vrxfull,
            peak: self.peak,
            underflows: self.underflow.count,
            overflows: self.overflow.count,
            margin_us: self.margin.stats(),
            method: "event history, each packet read at its own time, over the whole capture".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(num: u64, den: u64) -> Rational {
        Rational::new(num, den).unwrap()
    }

    #[test]
    fn rounds_halves_away_from_zero() {
        assert_eq!(
            [round_div(5, 2), round_div(-5, 2), round_div(4, 2), round_div(3, 2), round_div(1, 3)],
            [3, -3, 2, 2, 0]
        );
    }

    #[test]
    fn unwraps_near_the_arrival() {
        let t = 1_790_510_437_123_456_789;
        let now = t * CLOCK / NANOS;
        assert_eq!(unwrap(now as u32, t, CLOCK), now);
        assert_eq!(unwrap((now - 1501) as u32, t, CLOCK), now - 1501);
        assert_eq!(unwrap((now + 5) as u32, t, CLOCK), now + 5);
    }

    #[test]
    fn works_out_frame_rates() {
        let stamps =
            |step: &dyn Fn(u32) -> u32| (0..12).map(|i| 1_000_000_u32.wrapping_add(step(i))).collect::<Vec<_>>();
        assert_eq!(frame_rate_from(&stamps(&|i| i * 1800), 1), Some(rate(50, 1)));
        assert_eq!(frame_rate_from(&stamps(&|i| i * 1800), 2), Some(rate(25, 1)));
        // 1501 and 1502 in turn: 59.94.
        assert_eq!(frame_rate_from(&stamps(&|i| i * 3003 / 2), 1), Some(rate(60000, 1001)));
        assert_eq!(frame_rate_from(&stamps(&|i| i * 1234), 1), None);
        assert_eq!(frame_rate_from(&[5], 1), None);
    }

    #[test]
    fn cmax_follows_the_formulas() {
        // 1080p59.94 at 4320 packets a frame: the worked values in the notes, 6 / 5 / 16.
        let c = Cmax::new(rate(60000, 1001), 4320, (1080, 1125));
        assert_eq!(c, Cmax { narrow: 6, narrow_linear: 5, wide: Some(16) });
        // 2160p59.94 at 17280 packets: over 900 000 packets a second, no Type W formula.
        let c = Cmax::new(rate(60000, 1001), 17_280, (1080, 1125));
        assert_eq!((c.narrow, c.narrow_linear, c.wide), (24, 23, None));
    }

    #[test]
    fn schedules_reads() {
        // 1080p50, 40 packets a frame, gapped: TRS = 20 ms × 1080/1125 ÷ 40 = 480 µs,
        // TRODEFAULT = 43/1125 × 20 ms = 764.444… µs.
        let raster = Raster::new(false, Some(1080));
        let s = Schedule::new(rate(50, 1), 40, true, raster, false, None);
        let ns = |v: i128| v as f64 / s.scale as f64;
        assert!((ns(s.read(0, 0)) - 764_444.444).abs() < 0.001);
        assert!((ns(s.read(0, 1) - s.read(0, 0)) - 480_000.0).abs() < 1e-9);
        assert!((ns(s.read(1, 0) - s.read(0, 0)) - 20_000_000.0).abs() < 1e-9);
        // Signalled TROFF, and the linear schedule: TRS = 20 ms ÷ 40.
        let s = Schedule::new(rate(50, 1), 40, false, raster, false, Some(100));
        assert_eq!(s.read(0, 0) / s.scale, 100_000);
        assert_eq!((s.read(0, 1) - s.read(0, 0)) / s.scale, 500_000);
        // 1080i50 gapped: the second field's reads start half a frame after the first's.
        let raster = Raster::new(true, Some(1080));
        let s = Schedule::new(rate(25, 1), 40, true, raster, true, None);
        assert_eq!(s.read(0, 20) - s.read(0, 0), s.frame / 2);
        assert!((s.offset as f64 / s.scale as f64 - 22.0 / 1125.0 * 40_000_000.0).abs() < 0.001);
        // The nearest transmission slot.
        let tpa0 = 7 * 40_000_000 + 900_000;
        assert_eq!(s.frame_index(tpa0), 7);
        assert_eq!(s.frame_index(7 * 40_000_000 - 2_000_000), 7);
    }

    #[test]
    fn cinst_drains_on_epoch_instants() {
        // 50 fps, 40 packets: TDRAIN = 20 ms ÷ 44 = 454.5 µs.
        let mut c = Cinst::new(rate(50, 1), 40, Cmax::new(rate(50, 1), 40, (1080, 1125)), Some(4), Some(4));
        let t0 = 1_000_000_000;
        for i in 0..6 {
            c.arrive(t0 + i);
        }
        assert_eq!((c.peak, c.exceeded.count), (6, 2));
        // Two drains later the bucket holds 4, and one more packet makes 5.
        c.arrive(t0 + 2 * 454_546);
        assert_eq!(c.level, 5);
        c.arrive(t0 + 1_000_000_000);
        assert_eq!(c.level, 1);
    }

    #[test]
    fn cinst_counts_every_burst_over_the_limit() {
        // Without a sender type, a level fails only over the widest CMAX, however many there are.
        let cmax = Cmax::new(rate(50, 1), 40, (1080, 1125));
        let widest = cmax.widest();
        assert_eq!(widest, 16);
        let mut c = Cinst::new(rate(50, 1), 40, cmax, None, Some(widest));
        let bursts = 100_000;
        for burst in 0..bursts {
            let t = 1_000_000_000 + burst * 20_000_000;
            for i in 0..20 {
                c.arrive(t + i);
            }
        }
        assert_eq!((c.peak, c.exceeded.count), (20, 4 * bursts as u64));
    }

    #[test]
    fn a_wide_sender_has_no_cmax_at_900k_packets_a_second() {
        // 2160p60 in 15,000 packets a frame: 900,000 packets a second.
        let cmax = Cmax::new(rate(60, 1), 15_000, (2160, 2250));
        assert_eq!(cmax.wide, None);
        let cmax = Cmax::new(rate(60, 1), 14_999, (2160, 2250));
        assert_eq!(cmax.wide, Some(41));
    }
}
