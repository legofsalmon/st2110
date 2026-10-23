//! Checks on what the payloads hold, for the streams whose SDP file says they carry
//! ST 2110-40 ancillary data, ST 2110-31 AES3, ST 2110-41 fast metadata or ST 2110-43
//! timed text: the payload formats, and the sending rules that need them read.

use st2110_sdp::{Essence, Rational, Rule};

use crate::report::{FastMetadataReport, Finding};
use crate::rtp::{self, AncField, AncPacket, Header};
use crate::stats::{NANOS, Tally};
use crate::video::{Bucket, round_div, unwrap};
use crate::{Timeline, plural, rules};

/// The RTP clock rate of ancillary data, in Hz (ST 2110-40:2023 §5.3).
const ANC_CLOCK: i128 = 90_000;

/// The longest a fast metadata stream may go without a packet (ST 2110-41:2026 §5.1).
const FMX_INTERVAL: i128 = 500_000_000;

/// The shortest time ST 2110-41:2026 §7 asks R_NOMINAL be averaged over.
const NCM_AVERAGE: i128 = 10 * NANOS;

/// Arrivals held until R_NOMINAL is known. A stream with more takes R_NOMINAL from these.
const NCM_HOLD: usize = 4_000_000;

/// The fewest total lines of any format in ST 2059-1:2021 §7, which makes the longest
/// LLTM T_D of ST 2110-40:2023 §6.4 at a frame rate.
const FEWEST_LINES: i128 = 525;

/// What the SDP file says that the checks use.
#[derive(Clone, Debug, Default)]
pub(crate) struct DataConfig {
    /// `DID_SDID`: the ANC packet types listed, if any are.
    pub did_sdid: Vec<(u8, u8)>,
    /// Whether `VPID_Code` is signalled.
    pub vpid: bool,
    /// `TM`, as signalled.
    pub tm: Option<String>,
    /// `exactframerate`.
    pub frame_rate: Option<Rational>,
    /// `TROFF`, in microseconds.
    pub troff_us: Option<u32>,
    /// The AM824 subframes in each sample period: the `a=rtpmap` channel count.
    pub channels: Option<u16>,
}

/// A packet as the checks see it.
pub(crate) struct Packet<'a> {
    /// Arrival, on the analysis timeline.
    pub t: i128,
    /// The sequence number, extended as the flow extends it.
    pub seq: u32,
    pub header: Header,
    /// The RTP header's CSRC count.
    pub csrcs: u8,
    /// The payload, from the end of the RTP header to any padding.
    pub payload: &'a [u8],
}

/// A count of packets with something wrong, and what the first of them had wrong.
#[derive(Default)]
struct Problems {
    tally: Tally,
    first: Option<String>,
}

impl Problems {
    fn hit(&mut self, t: i128, problem: impl FnOnce() -> String) {
        self.tally.hit(t);
        if self.first.is_none() {
            self.first = Some(problem());
        }
    }

    /// The finding, when there were any: `what` describes the count, as `3 packets`.
    fn finding(&self, rule: &'static Rule, flow: usize, timeline: &Timeline, what: &str) -> Option<Finding> {
        let first = self.first.as_deref()?;
        let message = format!("{} {what}; the first: {first}", plural(self.tally.count, "packet"));
        Some(Finding::new(rule, message, Some(flow), None, timeline.at(self.tally.first), self.tally.count))
    }
}

/// The payload checks a flow gets.
pub(crate) enum DataEngine {
    Anc(Box<AncEngine>),
    Am824(Am824Engine),
    Fmx(FmxEngine),
    Ttml(TtmlEngine),
}

impl DataEngine {
    /// The checks for a stream of `essence`, if it has any. `absolute` says whether times
    /// are PTP time, which the send time checks need.
    pub(crate) fn new(essence: Essence, config: DataConfig, absolute: bool) -> Option<Self> {
        match essence {
            Essence::Ancillary => Some(Self::Anc(Box::new(AncEngine::new(config, absolute)))),
            Essence::Aes3 => Some(Self::Am824(Am824Engine::new(config.channels))),
            Essence::FastMetadata => Some(Self::Fmx(FmxEngine::default())),
            Essence::TimedText => Some(Self::Ttml(TtmlEngine::default())),
            _ => None,
        }
    }

    /// Takes the next packet, in arrival order.
    pub(crate) fn push(&mut self, p: &Packet<'_>) {
        match self {
            Self::Anc(engine) => engine.push(p),
            Self::Am824(engine) => engine.push(p),
            Self::Fmx(engine) => engine.push(p),
            Self::Ttml(engine) => engine.push(p),
        }
    }

    /// The findings, and the fast metadata measurements for an ST 2110-41 stream.
    pub(crate) fn finish(self, flow: usize, timeline: &Timeline) -> (Vec<Finding>, Option<FastMetadataReport>) {
        match self {
            Self::Anc(engine) => (engine.finish(flow, timeline), None),
            Self::Am824(engine) => (engine.finish(flow, timeline), None),
            Self::Fmx(engine) => engine.finish(flow, timeline),
            Self::Ttml(engine) => (engine.finish(flow, timeline), None),
        }
    }
}

/// The last packet in sequence: its sequence number, timestamp and whether it named a
/// field.
#[derive(Clone, Copy)]
struct AncLast {
    seq: u32,
    timestamp: u32,
    field: bool,
}

/// A data stream and channel that ANC packets propose: the stream number, if given, and
/// whether it is the colour-difference channel.
type Channel = (Option<u8>, bool);

/// A proposed location: the line and the horizontal offset.
type Location = (u16, u16);

/// ST 2110-40 ancillary data: the RFC 8331 payload, the keep-alive packets, the
/// locations proposed and the transmission model.
pub(crate) struct AncEngine {
    config: DataConfig,
    absolute: bool,
    last: Option<AncLast>,
    /// Frames or fields with no packet, counted on the packet after them.
    missing: Tally,
    missing_unit: &'static str,
    payload: Problems,
    field: Tally,
    unlisted: Problems,
    audio_edh: Problems,
    no_vpid: Tally,
    disorder: Problems,
    /// The timestamp of the frame whose locations are being followed, and the last
    /// location proposed in it on each data stream and channel.
    locations: Option<(u32, Vec<(Channel, Location)>)>,
    late: Tally,
    early: Tally,
}

impl AncEngine {
    fn new(config: DataConfig, absolute: bool) -> Self {
        Self {
            config,
            absolute,
            last: None,
            missing: Tally::default(),
            missing_unit: "frame",
            payload: Problems::default(),
            field: Tally::default(),
            unlisted: Problems::default(),
            audio_edh: Problems::default(),
            no_vpid: Tally::default(),
            disorder: Problems::default(),
            locations: None,
            late: Tally::default(),
            early: Tally::default(),
        }
    }

    /// The transmission model, and whether `TM` named it.
    fn model(&self) -> (&'static str, bool) {
        match self.config.tm.as_deref() {
            Some(tm) if tm.eq_ignore_ascii_case("LLTM") => ("LLTM", true),
            Some(tm) if tm.eq_ignore_ascii_case("CTM") => ("CTM", true),
            _ => ("CTM", false),
        }
    }

    fn push(&mut self, p: &Packet<'_>) {
        let h = p.header;
        let Some(header) = rtp::anc_header(p.payload) else {
            self.payload.hit(p.t, || "the payload is shorter than its 8-octet header".into());
            return;
        };
        if header.field == AncField::Invalid {
            self.field.hit(p.t);
        }
        let field = matches!(header.field, AncField::First | AncField::Second);
        self.keepalive(p, field);
        self.send_time(p, header.field == AncField::Second);
        let data = &p.payload[8..];
        let packets = if usize::from(header.length) != data.len() {
            Err(format!("Length says {} octets, but {} follow the payload header", header.length, data.len()))
        } else if rtp::anc_reserved(p.payload).is_some_and(|r| r != 0) {
            Err("the payload header's reserved bits are not 0".into())
        } else {
            rtp::anc_packets(data, header.count)
        };
        match packets {
            Ok(packets) => self.packets(p.t, h.timestamp, &packets),
            Err(problem) => self.payload.hit(p.t, || problem),
        }
    }

    /// Counts the frames or fields that passed with no packet: those between two
    /// timestamps of packets in sequence, with none lost between them.
    fn keepalive(&mut self, p: &Packet<'_>, field: bool) {
        let timestamp = p.header.timestamp;
        let last = self.last.replace(AncLast { seq: p.seq, timestamp, field });
        let Some(last) = last else { return };
        let Some(rate) = self.config.frame_rate else { return };
        if p.seq != last.seq.wrapping_add(1) || last.field != field {
            return;
        }
        let ticks = i128::from(timestamp.wrapping_sub(last.timestamp) as i32);
        if ticks <= 0 {
            return;
        }
        let per_frame = if field { 2 } else { 1 };
        let units =
            round_div(ticks * i128::from(rate.numerator()) * per_frame, ANC_CLOCK * i128::from(rate.denominator()));
        if units > 1 {
            let missed = u64::try_from(units - 1).unwrap_or(u64::MAX);
            self.missing.count = self.missing.count.saturating_add(missed);
            self.missing.first.get_or_insert(p.t);
            if field {
                self.missing_unit = "field";
            }
        }
    }

    /// Checks the time the packet arrived against the window of ST 2110-40:2023 §6.4
    /// and §6.5. T_EPO needs the line timing of the SDI format, which the SDP file does
    /// not give, so the window is widened to hold any T_EPO: from 0 to a frame after the
    /// frame starts. The frame starts at the time its timestamp names, or half a frame
    /// before that for the second field, unless `TROFF` moves it, when only the late
    /// limit is checked.
    fn send_time(&mut self, p: &Packet<'_>, second_field: bool) {
        let Some(rate) = self.config.frame_rate.filter(|_| self.absolute) else { return };
        let (num, den) = (i128::from(rate.numerator()), i128::from(rate.denominator()));
        let frame = den * NANOS / num;
        let sampled = unwrap(p.header.timestamp, p.t, ANC_CLOCK) * NANOS / ANC_CLOCK;
        let since_start = p.t - sampled + if second_field { frame / 2 } else { 0 };
        let low_latency = self.model().0 == "LLTM";
        // The longest T_D, and the shortest.
        let (most, least) = if low_latency {
            ((8 * den * NANOS + num * FEWEST_LINES - 1) / (num * FEWEST_LINES), 0)
        } else {
            (1_000_000, 1_000_000)
        };
        let troff = self.config.troff_us.map(|us| i128::from(us) * 1000);
        // The timestamp truncates the frame start to the 90 kHz clock: a tick of slack.
        let tick = (NANOS + ANC_CLOCK - 1) / ANC_CLOCK;
        if since_start > frame + most + tick + troff.unwrap_or(0) {
            self.late.hit_max(p.t, since_start as f64 / 1000.0);
        }
        if troff.is_none() && since_start < least - frame {
            self.early.hit_min(p.t, since_start as f64 / 1000.0);
        }
    }

    fn packets(&mut self, t: i128, timestamp: u32, packets: &[AncPacket]) {
        if self.locations.as_ref().is_none_or(|(ts, _)| *ts != timestamp) {
            self.locations = Some((timestamp, Vec::new()));
        }
        for (i, packet) in packets.iter().enumerate() {
            let n = i + 1;
            if let Some(problem) = packet.word_problem() {
                self.payload.hit(t, || format!("ANC packet {n}: {problem}"));
            }
            let (did, sdid) = packet.type_id();
            if !self.config.did_sdid.is_empty() && !self.config.did_sdid.contains(&(did, sdid)) {
                self.unlisted.hit(t, || format!("ANC packet {n} is DID {did:#04X} SDID {sdid:#04X}"));
            }
            if let Some(what) = st2110_sdp::data::audio_or_edh(did) {
                self.audio_edh.hit(t, || format!("ANC packet {n} is DID {did:#04X}, {what}"));
            }
            if packet.exact_location() && !self.config.vpid {
                self.no_vpid.hit(t);
            }
            self.order(t, n, packet);
        }
    }

    /// Checks that the packet's line, and its offset on a line already used, come after
    /// those proposed before it in the frame, on the same data stream and channel.
    fn order(&mut self, t: i128, n: usize, packet: &AncPacket) {
        if packet.line >= rtp::ANC_HIGH_LINE {
            return;
        }
        let (_, seen) = self.locations.as_mut().expect("set for the frame");
        let channel = (packet.stream, packet.chroma);
        let here = (packet.line, packet.horizontal);
        match seen.iter_mut().find(|(c, _)| *c == channel) {
            Some((_, last)) => {
                let exact = last.1 < rtp::ANC_REGION_OFFSET && here.1 < rtp::ANC_REGION_OFFSET;
                let backwards = here.0 < last.0 || (here.0 == last.0 && exact && here.1 <= last.1);
                if backwards {
                    let before = *last;
                    self.disorder.hit(t, || {
                        format!(
                            "ANC packet {n} proposes line {} word {}, after line {} word {}",
                            here.0, here.1, before.0, before.1
                        )
                    });
                }
                *last = here;
            }
            None => seen.push((channel, here)),
        }
    }

    fn finish(self, flow: usize, timeline: &Timeline) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
            if tally.count > 0 {
                findings.push(Finding::new(rule, message, Some(flow), None, timeline.at(tally.first), tally.count));
            }
        };
        add(
            &rules::ANC_KEEPALIVE,
            &self.missing,
            format!(
                "{} passed with no packet, though none was lost: a {} with no ANC data still needs a packet with ANC_Count 0 and the marker set",
                plural(self.missing.count, self.missing_unit),
                self.missing_unit
            ),
        );
        add(&rules::ANC_FIELD, &self.field, format!("{} had the F field 0b01", plural(self.field.count, "packet")));
        add(
            &rules::ANC_LOCATION,
            &self.no_vpid,
            format!(
                "{} proposed an exact line or data stream, but the SDP file signals no VPID_Code to say which SDI format it is in",
                plural(self.no_vpid.count, "ANC packet")
            ),
        );
        let (model, named) = self.model();
        let model = if named { model.to_string() } else { format!("{model}, taken as TM is absent,") };
        let td = if model.starts_with("LLTM") { "8 line times" } else { "1 ms" };
        add(
            &rules::ANC_SEND_TIME,
            &self.late,
            format!(
                "{} arrived as much as {:.1} µs after the start of their frame, later than {model} allows even for the last packet of a frame: a frame period and {td}{}",
                plural(self.late.count, "packet"),
                self.late.worst.unwrap_or_default(),
                if self.config.troff_us.is_some() { " after the frame start that TROFF gives" } else { "" }
            ),
        );
        add(
            &rules::ANC_SEND_TIME,
            &self.early,
            format!(
                "{} arrived as much as {:.1} µs before the start of their frame, earlier than {model} allows: no more than a frame before the deadline, which is {td} or more after the frame starts",
                plural(self.early.count, "packet"),
                -self.early.worst.unwrap_or_default()
            ),
        );
        findings.extend(self.payload.finding(&rules::ANC_PAYLOAD, flow, timeline, "had malformed payloads"));
        findings.extend(self.unlisted.finding(
            &rules::ANC_DID_SDID,
            flow,
            timeline,
            "carried ANC packets of types the SDP file's DID_SDID does not list",
        ));
        findings.extend(self.audio_edh.finding(
            &rules::ANC_AUDIO_EDH_PACKETS,
            flow,
            timeline,
            "carried embedded audio or EDH packets",
        ));
        findings.extend(self.disorder.finding(
            &rules::ANC_LOCATION,
            flow,
            timeline,
            "proposed locations earlier in the frame than the packets before them",
        ));
        findings
    }
}

/// AES3 frames in a block, over which the channel status runs, one bit a frame.
const BLOCK_FRAMES: usize = 192;

/// The AM824 block start and channel status bits.
const AM824_B: u8 = 0x20;
const AM824_C: u8 = 0x04;

/// Where one AES3 signal's frames are in its block, once a B bit has said, and the
/// channel status each of its two subframes has brought so far.
#[derive(Clone, Default)]
struct Aes3Signal {
    frame: Option<usize>,
    status: [[u8; 24]; 2],
}

/// The AES3 channel status CRC (AES3-2-2009 §5): x⁸ + x⁴ + x³ + x² + 1 from all ones,
/// over the bits in the order they are sent, least significant first.
fn status_crc(bytes: &[u8]) -> u8 {
    let mut crc = 0xFFu8;
    for &byte in bytes {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xB8 } else { crc >> 1 };
        }
    }
    crc
}

/// ST 2110-31 AES3: the header, the AM824 subframes, their parity, and each signal's
/// 192-frame blocks of channel status.
pub(crate) struct Am824Engine {
    channels: Option<usize>,
    header: Problems,
    subframes: Problems,
    parity: Problems,
    blocks: Problems,
    status: Problems,
    signals: Vec<Aes3Signal>,
    last_seq: Option<u32>,
}

impl Am824Engine {
    fn new(channels: Option<u16>) -> Self {
        let channels = channels.map(usize::from).filter(|&n| n > 0 && n % 2 == 0);
        Self {
            channels,
            header: Problems::default(),
            subframes: Problems::default(),
            parity: Problems::default(),
            blocks: Problems::default(),
            status: Problems::default(),
            signals: vec![Aes3Signal::default(); channels.unwrap_or(0) / 2],
            last_seq: None,
        }
    }

    fn push(&mut self, p: &Packet<'_>) {
        if p.header.marker || p.csrcs != 0 {
            let (marker, csrcs) = (p.header.marker, p.csrcs);
            self.header.hit(p.t, || match (marker, csrcs) {
                (true, 0) => "the marker bit is set".into(),
                (false, n) => format!("the CSRC count is {n}"),
                (true, n) => format!("the marker bit is set and the CSRC count is {n}"),
            });
        }
        // A loss leaves each signal's place in its block unknown until its next B bit.
        if self.last_seq.replace(p.seq).is_some_and(|last| p.seq != last.wrapping_add(1)) {
            for signal in &mut self.signals {
                signal.frame = None;
            }
        }
        // A payload that is not whole sample periods is the channel count's finding.
        let Some(channels) = self.channels else { return };
        if p.payload.is_empty() || !p.payload.len().is_multiple_of(4 * channels) {
            return;
        }
        for (i, subframe) in p.payload.as_chunks::<4>().0.iter().enumerate() {
            let (sample, channel) = (i / channels + 1, i % channels);
            let first = channel % 2 == 0;
            let (start, block, frame) = (subframe[0] & 0xC0, subframe[0] & 0x20 != 0, subframe[0] & 0x10 != 0);
            let problem = if start != 0 {
                Some("starts with bits other than 00")
            } else if frame != first {
                Some(if first {
                    "has F clear, on the first subframe of its AES3 frame"
                } else {
                    "has F set, on the second subframe of its AES3 frame"
                })
            } else if block && !first {
                Some("has B set, on the second subframe of its AES3 frame")
            } else {
                None
            };
            if let Some(problem) = problem {
                self.subframes.hit(p.t, || {
                    format!(
                        "subframe {} of AES3 signal {} in sample period {sample} {problem}",
                        channel % 2 + 1,
                        channel / 2 + 1
                    )
                });
                for signal in &mut self.signals {
                    signal.frame = None;
                }
                return;
            }
        }
        self.aes3_bits(p, channels);
    }

    /// The parity of each subframe, and each signal's blocks: a B bit every 192 frames,
    /// and the channel status they carry, checked by its CRC.
    fn aes3_bits(&mut self, p: &Packet<'_>, channels: usize) {
        let mut parity = None;
        let mut block = None;
        let mut status = None;
        for (sample, frames) in p.payload.chunks_exact(4 * channels).enumerate() {
            let subframes = frames.as_chunks::<4>().0;
            for (channel, subframe) in subframes.iter().enumerate() {
                // P evens out time slots 4 to 31: the audio and the V, U, C and P bits.
                if parity.is_none() && !(u32::from_be_bytes(*subframe) & 0x0FFF_FFFF).count_ones().is_multiple_of(2) {
                    parity = Some(format!(
                        "subframe {} of AES3 signal {} in sample period {} has odd parity",
                        channel % 2 + 1,
                        channel / 2 + 1,
                        sample + 1
                    ));
                }
            }
            for (s, signal) in self.signals.iter_mut().enumerate() {
                let pair = [subframes[2 * s][0], subframes[2 * s + 1][0]];
                let started = pair[0] & AM824_B != 0;
                match (signal.frame, started) {
                    (Some(k), true) if k != 0 => {
                        block.get_or_insert_with(|| {
                            format!("AES3 signal {} had a B bit {k} frames into its block", s + 1)
                        });
                    }
                    (Some(0), false) => {
                        block.get_or_insert_with(|| {
                            format!("AES3 signal {} had no B bit 192 frames after the last", s + 1)
                        });
                        signal.frame = None;
                        continue;
                    }
                    (None, false) => continue,
                    _ => {}
                }
                let k = if started { 0 } else { signal.frame.unwrap_or(0) };
                if k == 0 {
                    signal.status = [[0; 24]; 2];
                }
                for (bits, flags) in signal.status.iter_mut().zip(pair) {
                    if flags & AM824_C != 0 {
                        bits[k / 8] |= 1 << (k % 8);
                    }
                }
                if k + 1 < BLOCK_FRAMES {
                    signal.frame = Some(k + 1);
                    continue;
                }
                signal.frame = Some(0);
                for (sub, bits) in signal.status.iter().enumerate() {
                    // Professional use ends with a CRC; a minimum implementation sends 0.
                    if bits[0] & 1 == 1 && bits[23] != 0 && status_crc(&bits[..23]) != bits[23] {
                        status.get_or_insert_with(|| {
                            format!(
                                "subframe {} of AES3 signal {} sent channel status whose CRC is {:#04X}, not {:#04X}",
                                sub + 1,
                                s + 1,
                                bits[23],
                                status_crc(&bits[..23])
                            )
                        });
                    }
                }
            }
        }
        for (problems, problem) in [(&mut self.parity, parity), (&mut self.blocks, block), (&mut self.status, status)] {
            if let Some(problem) = problem {
                problems.hit(p.t, || problem);
            }
        }
    }

    fn finish(self, flow: usize, timeline: &Timeline) -> Vec<Finding> {
        let header =
            self.header.finding(&rules::AM824_HEADER, flow, timeline, "had RTP headers ST 2110-31 does not allow");
        let subframes =
            self.subframes.finding(&rules::AM824_SUBFRAME, flow, timeline, "had AM824 subframes out of AES3 framing");
        let parity = self.parity.finding(&rules::AM824_PARITY, flow, timeline, "had AM824 subframes with odd parity");
        let blocks = self.blocks.finding(&rules::AM824_BLOCK, flow, timeline, "broke an AES3 signal's 192-frame block");
        let status = self.status.finding(
            &rules::AM824_STATUS,
            flow,
            timeline,
            "ended a block of channel status with a wrong CRC",
        );
        [header, subframes, parity, blocks, status].into_iter().flatten().collect()
    }
}

/// ST 2110-41 fast metadata: the marker bit, the longest wait for a packet, the Data
/// Item Packages and the network compatibility model.
#[derive(Default)]
pub(crate) struct FmxEngine {
    /// The last packet's arrival and sequence number.
    last: Option<(i128, u32)>,
    marker: Tally,
    silent: Tally,
    payload: Problems,
    ncm: Ncm,
}

/// The ST 2110-41:2026 §7 network compatibility model: the ST 2110-21 bucket, drained
/// at a rate and judged against a C_MAX that both follow from R_NOMINAL, the stream's
/// long-term average packet rate. That is known only at the end, so arrivals are held
/// until then.
#[derive(Default)]
struct Ncm {
    /// The first arrival, which held arrivals count from.
    first: Option<i128>,
    last: i128,
    packets: u64,
    held: Vec<i64>,
    run: Option<NcmRun>,
}

/// The model, once R_NOMINAL is known.
struct NcmRun {
    bucket: Bucket,
    /// R_NOMINAL as packets over nanoseconds.
    rate: (u64, i128),
    cmax: u32,
    exceeded: Tally,
}

impl Ncm {
    fn push(&mut self, t: i128) {
        self.packets += 1;
        let first = *self.first.get_or_insert(t);
        self.last = self.last.max(t);
        if let Some(run) = &mut self.run {
            run.arrive(t);
            return;
        }
        self.held.push(i64::try_from(t - first).unwrap_or(i64::MAX));
        if self.held.len() >= NCM_HOLD {
            self.start();
        }
    }

    /// Works out R_NOMINAL from the packets so far and runs the held arrivals through the
    /// bucket. It needs two packets, some time apart.
    fn start(&mut self) {
        let Some(first) = self.first else { return };
        let span = self.last - first;
        if self.packets < 2 || span <= 0 {
            return;
        }
        let packets = self.packets - 1;
        let n = i128::from(packets);
        // 1 ÷ T_DRAIN = MAX(800, 1.1 × R_NOMINAL) drains a second, as drains a nanosecond.
        let drain = if 11 * n * NANOS > 8000 * span { (11 * n, 10 * span) } else { (800, NANOS) };
        let cmax = u32::try_from(n * NANOS / (43_200 * span)).unwrap_or(u32::MAX).max(4);
        let mut run = NcmRun { bucket: Bucket::new(drain), rate: (packets, span), cmax, exceeded: Tally::default() };
        for offset in std::mem::take(&mut self.held) {
            run.arrive(first + i128::from(offset));
        }
        self.run = Some(run);
    }

    fn finish(mut self, flow: usize, timeline: &Timeline) -> Option<(FastMetadataReport, Option<Finding>)> {
        if self.run.is_none() {
            self.start();
        }
        let run = self.run?;
        let (packets, span) = run.rate;
        let report = FastMetadataReport {
            r_nominal: packets as f64 * 1e9 / span as f64,
            averaged_s: span as f64 / 1e9,
            estimate: span < NCM_AVERAGE,
            drain_us: run.bucket.drain_us(),
            cmax: run.cmax,
            peak: run.bucket.peak(),
        };
        let finding = (run.exceeded.count > 0).then(|| {
            let average = if report.estimate {
                format!(
                    "averaged over the whole capture's {:.1} s, short of the 10 s ST 2110-41 asks for, so it and C_MAX are estimates",
                    report.averaged_s
                )
            } else {
                format!("averaged over {:.1} s", report.averaged_s)
            };
            let message = format!(
                "CINST reached {}, over C_MAX {}, on {}; T_DRAIN is {:.1} µs, from an R_NOMINAL of {:.1} packets a second {average}",
                report.peak,
                report.cmax,
                plural(run.exceeded.count, "packet"),
                report.drain_us,
                report.r_nominal
            );
            Finding::new(
                &rules::FMX_CINST,
                message,
                Some(flow),
                None,
                timeline.at(run.exceeded.first),
                run.exceeded.count,
            )
        });
        Some((report, finding))
    }
}

impl NcmRun {
    fn arrive(&mut self, t: i128) {
        let level = self.bucket.arrive(t);
        if level > u64::from(self.cmax) {
            self.exceeded.hit_max(t, level as f64);
        }
    }
}

impl FmxEngine {
    fn push(&mut self, p: &Packet<'_>) {
        if p.header.marker {
            self.marker.hit(p.t);
        }
        if let Some((last_t, last_seq)) = self.last.replace((p.t, p.seq))
            && p.seq == last_seq.wrapping_add(1)
            && p.t - last_t > FMX_INTERVAL
        {
            self.silent.hit_max(p.t, (p.t - last_t) as f64 / 1e6);
        }
        if let Some(problem) = fmx_problem(p.payload) {
            self.payload.hit(p.t, || problem);
        }
        self.ncm.push(p.t);
    }

    fn finish(self, flow: usize, timeline: &Timeline) -> (Vec<Finding>, Option<FastMetadataReport>) {
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
            if tally.count > 0 {
                findings.push(Finding::new(rule, message, Some(flow), None, timeline.at(tally.first), tally.count));
            }
        };
        add(
            &rules::FMX_MARKER,
            &self.marker,
            format!("{} had the marker bit set", plural(self.marker.count, "packet")),
        );
        add(
            &rules::FMX_INTERVAL,
            &self.silent,
            format!(
                "the stream went {} without a packet, though none was lost, the longest for {:.1} ms",
                plural(self.silent.count, "time"),
                self.silent.worst.unwrap_or_default()
            ),
        );
        findings.extend(self.payload.finding(&rules::FMX_PAYLOAD, flow, timeline, "had malformed payloads"));
        let (report, finding) = self.ncm.finish(flow, timeline).unzip();
        findings.extend(finding.flatten());
        (findings, report)
    }
}

/// What is wrong with a fast metadata payload's Data Item Packages, if anything.
fn fmx_problem(payload: &[u8]) -> Option<String> {
    let mut at = 0;
    let mut n = 0;
    while at < payload.len() {
        n += 1;
        let Some(header) = payload.get(at..at + 4) else {
            return Some(format!(
                "{} octets after the last whole Data Item Package are too few for another",
                payload.len() - at
            ));
        };
        let header = u32::from_be_bytes(header.try_into().expect("four octets"));
        let words = (header & 0x1FF) as usize;
        if words == 0 {
            return Some(format!("Data Item Package {n}, of type {:#08X}, has a Data Item Length of 0", header >> 10));
        }
        let end = at + 4 + 4 * words;
        if end > payload.len() {
            return Some(format!(
                "Data Item Package {n} has a Data Item Length of {}, past the end of the payload",
                plural(words as u64, "word")
            ));
        }
        at = end;
    }
    None
}

/// ST 2110-43 timed text: the RFC 8759 payload header, and documents put together from
/// their packets.
#[derive(Default)]
pub(crate) struct TtmlEngine {
    last_seq: Option<u32>,
    /// The timestamp of the document whose packets are arriving, until its last.
    open: Option<u32>,
    /// The timestamp of the last whole document.
    finished: Option<u32>,
    /// After a loss, packets are skipped until one ends a document.
    resync: bool,
    documents: u64,
    payload: Problems,
    document: Problems,
    keepalive: Problems,
    lost: Tally,
}

impl TtmlEngine {
    fn push(&mut self, p: &Packet<'_>) {
        let h = p.header;
        let length = match p.payload.get(..4) {
            Some(head) => {
                let reserved = u16::from_be_bytes([head[0], head[1]]);
                let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
                let follows = p.payload.len() - 4;
                if reserved != 0 {
                    self.payload.hit(p.t, || format!("the reserved bits are {reserved:#06X}"));
                } else if length != follows {
                    self.payload.hit(p.t, || format!("Length says {length} octets, but {follows} follow the header"));
                }
                length
            }
            None => {
                self.payload.hit(p.t, || "the payload is shorter than its 4-octet header".into());
                return;
            }
        };
        let in_order = self.last_seq.is_none_or(|last| p.seq == last.wrapping_add(1));
        if !self.last_seq.is_none_or(|last| (p.seq.wrapping_sub(last) as i32) > 0) {
            // Late: the sequence has moved past it.
            return;
        }
        self.last_seq = Some(p.seq);
        if !in_order {
            if self.open.take().is_some() {
                self.lost.hit(p.t);
            }
            (self.finished, self.resync) = (None, true);
        }
        if self.resync {
            self.resync = !h.marker;
            return;
        }
        // A keep-alive, between documents (ST 2110-43:2021 §4.3). One anywhere else is
        // left out too, and said.
        if length == 0 {
            if !h.marker || self.open.is_some() {
                let (marker, open) = (h.marker, self.open.is_some());
                self.keepalive.hit(p.t, || match (marker, open) {
                    (false, false) => "an empty packet had its marker clear".into(),
                    (false, true) => "an empty packet came partway through a document, with its marker clear".into(),
                    _ => "an empty packet came partway through a document".into(),
                });
            }
            return;
        }
        match self.open {
            Some(timestamp) if timestamp != h.timestamp => {
                self.document.hit(p.t, || {
                    format!("a document's packets carried timestamps {timestamp} and then {}", h.timestamp)
                });
            }
            None if self.finished == Some(h.timestamp) => {
                self.document.hit(p.t, || format!("two documents in a row carried timestamp {}", h.timestamp));
            }
            _ => {}
        }
        let timestamp = *self.open.get_or_insert(h.timestamp);
        if h.marker {
            self.open = None;
            self.finished = Some(timestamp);
            self.documents += 1;
        }
    }

    fn finish(self, flow: usize, timeline: &Timeline) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(self.payload.finding(&rules::TTML_PAYLOAD, flow, timeline, "had malformed payload headers"));
        findings.extend(self.document.finding(&rules::TTML_DOCUMENT, flow, timeline, "broke a document's framing"));
        findings.extend(self.keepalive.finding(
            &rules::TTML_KEEPALIVE,
            flow,
            timeline,
            "came as keep-alives out of place",
        ));
        if self.lost.count > 0 {
            let message = format!(
                "{} lost a packet partway through, and so were lost whole; {} arrived whole. Documents that lost their first packets are not counted",
                plural(self.lost.count, "document"),
                plural(self.documents, "document")
            );
            findings.push(Finding::new(
                &rules::TTML_DOCUMENT_LOSS,
                message,
                Some(flow),
                None,
                timeline.at(self.lost.first),
                self.lost.count,
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fast_metadata_bucket_follows_r_nominal() {
        let timeline = Timeline { start: 0, shift: 0 };
        // 300 000 packets a second, evenly: C_MAX is INT(300 000 ÷ 43 200) = 6 and the
        // bucket drains at 330 000 a second, so it never holds more than 1.
        let mut ncm = Ncm::default();
        for k in 0..30_000 {
            ncm.push(1_000 * NANOS + k * 10_000 / 3);
        }
        let (report, finding) = ncm.finish(1, &timeline).unwrap();
        assert!(finding.is_none());
        assert_eq!((report.cmax, report.peak, report.estimate), (6, 1, true));
        assert!((report.r_nominal - 300_000.0).abs() < 1.0 && (report.drain_us - 1e6 / 330_000.0).abs() < 1e-3);
        // At 100 packets a second it drains at the floor of 800 a second: seven packets
        // within one T_DRAIN of 1.25 ms overfill a C_MAX of 4, held until the end.
        let mut ncm = Ncm::default();
        for k in 0..1_100 {
            let burst = if k == 500 { 7 } else { 1 };
            for j in 0..burst {
                ncm.push(1_000 * NANOS + k * 10_000_000 + j * 100_000);
            }
        }
        let (report, finding) = ncm.finish(1, &timeline).unwrap();
        assert_eq!((report.cmax, report.peak, report.estimate, report.drain_us), (4, 7, false, 1250.0));
        assert_eq!(finding.unwrap().count, 3);
        // One packet gives no rate.
        let mut ncm = Ncm::default();
        ncm.push(0);
        assert!(ncm.finish(1, &timeline).is_none());
    }

    #[test]
    fn reads_data_item_packages() {
        // Type 0x100, two words; then type 0x101, one word.
        let mut payload = (0x100_u32 << 10 | 2).to_be_bytes().to_vec();
        payload.extend([0; 8]);
        payload.extend((0x101_u32 << 10 | 1 << 9 | 1).to_be_bytes());
        payload.extend([0; 4]);
        assert_eq!(fmx_problem(&payload), None);
        assert_eq!(fmx_problem(&[]), None);
        assert_eq!(
            fmx_problem(&payload[..16]),
            Some("Data Item Package 2 has a Data Item Length of 1 word, past the end of the payload".into())
        );
        assert_eq!(
            fmx_problem(&payload[..14]),
            Some("2 octets after the last whole Data Item Package are too few for another".into())
        );
        assert_eq!(
            fmx_problem(&(0x100_u32 << 10).to_be_bytes()),
            Some("Data Item Package 1, of type 0x000100, has a Data Item Length of 0".into())
        );
    }
}
