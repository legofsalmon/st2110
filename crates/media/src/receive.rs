//! Receiving a stream: datagrams from each leg, merged, put back in sequence order,
//! checked and put back together.

use std::net::Ipv4Addr;

use crate::audio::{AudioCounts, AudioDepacketiser};
use crate::describe::{Description, Media};
use crate::merge::{Extender, LegCounts, Merger, Pace, Playout, Released, Skew, Verdict, receiver_class};
use crate::rtp;
use crate::video::{Depacketiser, FrameInfo, Layout, VideoCounts};

const NANOS: i128 = 1_000_000_000;

/// How long a receiver waits by default for a missing packet, for its copy on a leg
/// that runs behind or for one that comes out of order: 50 ms, as far as ST 2022-7
/// class B receivers allow the legs to differ.
pub const DEFAULT_MAX_SKEW_NS: i64 = 50_000_000;

/// The longest a receiver will wait: a second, more than class C's 450 ms.
pub const MOST_SKEW_NS: i64 = 1_000_000_000;

/// Where received pictures and sound go.
pub trait Sink {
    /// A video frame, whole or with packets missing, and its pixel groups.
    fn frame(&mut self, info: &FrameInfo, pixels: &[u8]) {
        let _ = (info, pixels);
    }

    /// Audio samples, interleaved, in order, with silence where packets are missing.
    fn samples(&mut self, samples: &[i32]) {
        let _ = samples;
    }
}

impl Sink for () {}

/// The least, mean and greatest of a measurement.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Spread {
    /// The least.
    pub min: f64,
    /// The mean.
    pub mean: f64,
    /// The greatest.
    pub max: f64,
    /// How many.
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Accumulator {
    min: f64,
    max: f64,
    sum: f64,
    count: u64,
}

impl Accumulator {
    fn add(&mut self, value: f64) {
        if self.count == 0 {
            (self.min, self.max) = (value, value);
        }
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.sum += value;
        self.count += 1;
    }

    fn spread(&self) -> Option<Spread> {
        (self.count > 0).then(|| Spread {
            min: self.min,
            mean: self.sum / self.count as f64,
            max: self.max,
            count: self.count,
        })
    }
}

/// What arrived on one leg.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LegReport {
    /// Where the leg goes, and where from.
    pub leg: String,
    /// Datagrams that arrived.
    pub datagrams: u64,
    /// Octets of UDP payload that arrived.
    pub octets: u64,
    /// Datagrams from another source than the leg's, left out.
    pub other_source: u64,
    /// RTP packets of another payload type, left out.
    pub other_payload_type: u64,
    /// Datagrams that are not RTP, or too short to be the stream's, left out.
    pub not_rtp: u64,
    /// The stream's packets on this leg.
    pub rtp: LegCounts,
}

/// What the video frames showed.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VideoReport {
    /// Packets a frame had, as the last frame to arrive whole with no gap in its
    /// sequence numbers had them.
    pub packets_per_frame: Option<u32>,
    /// Frames, packets and faults the depacketiser counted.
    pub counts: VideoCounts,
    /// Frames that never arrived at all: steps of more than one frame between the RTP
    /// timestamps of the frames either side, with the packets missing between to match.
    pub skipped: u64,
    /// Frames the RTP timestamps skip with no packets missing between: the sender paused
    /// or left them out, or its clock stepped on a few frames.
    pub unsent: u64,
    /// Steps between RTP timestamps that are not a whole number of frames.
    pub irregular: u64,
    /// Times the RTP timestamps and sequence numbers disagreed: the timestamps stood
    /// still or stepped back, or moved on fewer frames than the packets missing between.
    pub jumps: u64,
    /// Frames a second, by the arrival of their first packets.
    pub frame_rate: Option<f64>,
}

/// What the audio showed.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AudioReport {
    /// Packets, samples and faults the depacketiser counted.
    pub counts: AudioCounts,
    /// The loudest sample on each channel, in dB below full scale; `None` for silence.
    pub peaks: Vec<Option<f64>>,
}

/// What a receiver found.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Report {
    /// The stream's format.
    pub stream: String,
    /// Each leg, path 1 first.
    pub legs: Vec<LegReport>,
    /// Seconds from the first packet of the stream to the last.
    pub seconds: f64,
    /// Megabits a second of RTP that the merged stream carried.
    pub megabits_per_second: f64,
    /// The synchronisation source of the stream, since it last restarted.
    pub ssrc: Option<u32>,
    /// Packets passed on after merging the legs, in sequence order.
    pub passed: u64,
    /// Packets no leg delivered.
    pub lost: u64,
    /// Packets that came after the receiver had stopped waiting for them.
    pub too_late: u64,
    /// How long the receiver waits for a missing packet, in milliseconds.
    pub max_skew_ms: f64,
    /// Times the sender restarted: a new synchronisation source, or sequence numbers or
    /// timestamps that started again elsewhere.
    pub restarts: u64,
    /// Packets that fitted neither the stream nor a restart, left out.
    pub strays: u64,
    /// Packets from before the sender restarted that came after it, left out.
    pub stale: u64,
    /// How far apart the legs' copies arrived, with two legs.
    pub skew: Option<Skew>,
    /// The tightest ST 2022-7 receiver class that allows the skew: D, A, B or C.
    pub class: Option<String>,
    /// Microseconds from the instant each frame's RTP timestamp names to the arrival
    /// of its first packet, or for audio each packet's: the sender's and network's
    /// delay, when both clocks follow PTP.
    pub latency: Option<Spread>,
    /// For video.
    pub video: Option<VideoReport>,
    /// For audio.
    pub audio: Option<AudioReport>,
    /// What went wrong: nothing arrived, a leg received nothing, packets were lost after
    /// merging, frames were incomplete, audio had gaps.
    pub problems: Vec<String>,
    /// What is worth knowing but not wrong in itself: a leg's loss that the other made
    /// good, datagrams left out.
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct LegState {
    datagrams: u64,
    octets: u64,
    other_source: u64,
    other_type: u64,
    not_rtp: u64,
}

/// What the video frames showed so far.
#[derive(Clone, Copy, Debug, Default)]
struct Frames {
    /// Ticks of the 90 kHz clock a frame.
    step: f64,
    /// The last frame: its RTP timestamp and highest sequence number, and when its first
    /// packet arrived, unless receiving cut it off.
    last: Option<(u32, u32, Option<i128>)>,
    /// Frame periods between frames whose first packets came, and the nanoseconds
    /// between their arrivals.
    periods: u64,
    span: i128,
    skipped: u64,
    unsent: u64,
    irregular: u64,
    jumps: u64,
}

impl Frames {
    fn add(&mut self, info: &FrameInfo, packets_per_frame: Option<u32>, latency: &mut Accumulator) {
        // A frame cut off at the start did not arrive from its first packet.
        let arrival = (!info.cut).then_some(info.first_arrival);
        if let Some(at) = arrival {
            latency.add(since_timestamp(info.timestamp, at, 90_000) / 1000.0);
        }
        if let Some((timestamp, sequence, last_arrival)) = self.last {
            let step = f64::from(info.timestamp.wrapping_sub(timestamp) as i32);
            let frames = (step / self.step).round();
            // Frames' worth of packets missing between the two: a frame lost on the way took
            // its packets with it, and one the sender left out never had any.
            let between = info.first_sequence.wrapping_sub(sequence).wrapping_sub(1) as i32;
            let missing = match packets_per_frame {
                _ if between < 0 => None,
                Some(per) => Some(f64::from(between) / f64::from(per)),
                None => (between == 0).then_some(0.0),
            };
            // Up to two frames more than the timestamps skip, for packets missing from the
            // frames either side.
            if frames < 1.0 || missing.is_some_and(|n| n >= frames + 1.0) {
                self.jumps += 1;
            } else {
                if (step - frames * self.step).abs() > 1.5 {
                    self.irregular += 1;
                }
                let skipped = frames - 1.0;
                let lost = missing.map_or(skipped, |n| n.floor().min(skipped));
                self.skipped += lost as u64;
                self.unsent += (skipped - lost) as u64;
                if let (Some(at), Some(last)) = (arrival, last_arrival) {
                    self.periods += frames as u64;
                    self.span += at - last;
                }
            }
        }
        self.last = Some((info.timestamp, info.last_sequence, arrival));
    }
}

enum Essence {
    Video { depacketiser: Box<Depacketiser>, frames: Frames },
    Audio { depacketiser: AudioDepacketiser, extender: Extender },
}

/// A packet the merger holds until the next shows what it is.
struct Held {
    sequence: u32,
    at: i128,
    data: Vec<u8>,
}

/// Receives one stream: takes the datagrams that arrive on each leg, merges the legs,
/// puts the packets back in sequence order, puts frames or samples back together for a
/// [`Sink`], and reports what it found.
pub struct Session {
    description: Description,
    max_skew: i64,
    legs: Vec<LegState>,
    merger: Merger,
    playout: Playout,
    essence: Essence,
    held: Option<Held>,
    first: Option<i128>,
    last: i128,
    /// Octets of RTP passed on.
    octets: u64,
    latency: Accumulator,
}

impl Session {
    /// A receiver of the stream a description gives, that waits
    /// [`DEFAULT_MAX_SKEW_NS`] for a missing packet.
    pub fn new(description: &Description) -> Result<Self, String> {
        Self::with_max_skew(description, DEFAULT_MAX_SKEW_NS)
    }

    /// A receiver that waits up to `max_skew` nanoseconds for a missing packet: for its
    /// copy on a leg that runs behind, or for one that comes out of order. The packets
    /// after it wait too, so it holds up to that long's worth of them.
    pub fn with_max_skew(description: &Description, max_skew: i64) -> Result<Self, String> {
        description.check()?;
        if !(0..=MOST_SKEW_NS).contains(&max_skew) {
            return Err(format!("a wait of {} ms is not 0 to {} ms", max_skew as f64 / 1e6, MOST_SKEW_NS / 1_000_000));
        }
        let (essence, packets_per_second, pace) = match &description.media {
            Media::Video(format) => {
                // As this crate's senders cut frames up: others may cut them otherwise,
                // which the merger measures.
                let packets = Layout::new(format)?.packets() as f64;
                let frame = 90_000.0 / format.rate.to_f64();
                let depacketiser = Box::new(Depacketiser::new(format)?);
                (
                    Essence::Video { depacketiser, frames: Frames { step: frame, ..Frames::default() } },
                    packets * format.rate.to_f64(),
                    Pace { ticks_per_packet: frame / packets, slack: 2.0 * frame, clock_rate: 90_000.0 },
                )
            }
            Media::Audio(format) => {
                let per = f64::from(format.samples_per_packet);
                (
                    Essence::Audio { depacketiser: AudioDepacketiser::new(format)?, extender: Extender::default() },
                    f64::from(format.sample_rate) / per,
                    Pace { ticks_per_packet: per, slack: 2.0 * per, clock_rate: f64::from(format.sample_rate) },
                )
            }
        };
        let merger = Merger::new(description.legs.len(), Merger::window_for(packets_per_second, max_skew), pace);
        Ok(Self {
            legs: vec![LegState::default(); description.legs.len()],
            playout: Playout::new(max_skew, u64::from(merger.window())),
            merger,
            description: description.clone(),
            max_skew,
            essence,
            held: None,
            first: None,
            last: 0,
            octets: 0,
            latency: Accumulator::default(),
        })
    }

    /// The stream it receives.
    pub fn description(&self) -> &Description {
        &self.description
    }

    /// Takes a datagram's payload that arrived on leg `leg` from `source`, at `at`
    /// nanoseconds of TAI.
    pub fn push(&mut self, leg: usize, source: Ipv4Addr, at: i128, datagram: &[u8], sink: &mut impl Sink) {
        let state = &mut self.legs[leg];
        state.datagrams += 1;
        state.octets += datagram.len() as u64;
        if self.description.legs[leg].source.is_some_and(|s| s != source) {
            state.other_source += 1;
            return;
        }
        let Some(header) = rtp::read_header(datagram) else {
            state.not_rtp += 1;
            return;
        };
        if header.payload_type != self.description.payload_type {
            state.other_type += 1;
            return;
        }
        let sequence = match &self.essence {
            Essence::Video { .. } => match rtp::payload(datagram, &header) {
                [high, low, ..] => (u32::from(u16::from_be_bytes([*high, *low])) << 16) | u32::from(header.sequence),
                _ => {
                    state.not_rtp += 1;
                    return;
                }
            },
            Essence::Audio { extender, .. } => extender.extend(header.sequence),
        };
        self.first.get_or_insert(at);
        self.last = self.last.max(at);
        match self.merger.push(leg, header.ssrc, sequence, header.timestamp, at) {
            Verdict::First => self.play(sequence, at, datagram, sink),
            Verdict::Held => self.held = Some(Held { sequence, at, data: datagram.to_vec() }),
            Verdict::Resumed => {
                self.play_held(sink);
                self.play(sequence, at, datagram, sink);
            }
            Verdict::Restart => {
                // What came before plays out, and the new stream starts afresh.
                self.flush(None, sink);
                self.playout.reset();
                match &mut self.essence {
                    Essence::Video { depacketiser, frames } => {
                        depacketiser.reset();
                        frames.last = None;
                    }
                    Essence::Audio { depacketiser, extender } => {
                        depacketiser.reset();
                        extender.reset();
                    }
                }
                self.play_held(sink);
                self.play(sequence, at, datagram, sink);
            }
            Verdict::Copy | Verdict::TooLate | Verdict::Stale => {}
        }
    }

    /// Lets go the packets still waiting for missing ones, and finishes the frame being
    /// put together: call it when receiving stops, at `end` nanoseconds of TAI. A frame
    /// still arriving then was cut off.
    pub fn finish(&mut self, end: i128, sink: &mut impl Sink) {
        self.flush(Some(end), sink);
    }

    /// The last video frame that arrived whole.
    pub fn last_whole_frame(&self) -> Option<&[u8]> {
        match &self.essence {
            Essence::Video { depacketiser, .. } => depacketiser.last_whole(),
            Essence::Audio { .. } => None,
        }
    }

    /// Passes a packet of the stream to the playout.
    fn play(&mut self, sequence: u32, at: i128, data: &[u8], sink: &mut impl Sink) {
        let Self { playout, essence, latency, octets, description, .. } = self;
        if let Essence::Audio { extender, .. } = essence {
            extender.take(sequence);
        }
        let clock_rate = description.media.clock_rate();
        playout.push(sequence, at, data, |packet| release(essence, latency, octets, clock_rate, packet, sink));
    }

    fn play_held(&mut self, sink: &mut impl Sink) {
        if let Some(held) = self.held.take() {
            self.play(held.sequence, held.at, &held.data, sink);
        }
    }

    /// Lets go every packet the playout holds, and finishes the frame being put
    /// together: `end` when receiving stopped then, `None` when the stream did.
    fn flush(&mut self, end: Option<i128>, sink: &mut impl Sink) {
        let Self { playout, essence, latency, octets, description, .. } = self;
        let clock_rate = description.media.clock_rate();
        playout.finish(|packet| release(essence, latency, octets, clock_rate, packet, sink));
        if let Essence::Video { depacketiser, frames } = essence {
            let per_frame = depacketiser.packets_per_frame();
            depacketiser.flush(end, |info, pixels| {
                frames.add(info, per_frame, latency);
                sink.frame(info, pixels);
            });
        }
    }

    /// What it found so far.
    pub fn report(&self) -> Report {
        let merged = self.merger.counts();
        let played = self.playout.counts();
        let seconds = self.first.map_or(0.0, |first| (self.last - first) as f64 / 1e9);
        let megabits_per_second = if seconds > 0.0 { self.octets as f64 * 8.0 / seconds / 1e6 } else { 0.0 };
        let legs: Vec<LegReport> = self
            .legs
            .iter()
            .zip(&self.description.legs)
            .zip(&merged.legs)
            .map(|((s, leg), &rtp)| LegReport {
                leg: leg.to_string(),
                datagrams: s.datagrams,
                octets: s.octets,
                other_source: s.other_source,
                other_payload_type: s.other_type,
                not_rtp: s.not_rtp,
                rtp,
            })
            .collect();
        let mut report = Report {
            stream: self.description.media.to_string(),
            seconds,
            megabits_per_second,
            ssrc: self.merger.ssrc(),
            passed: played.released,
            lost: merged.lost,
            too_late: played.too_late,
            max_skew_ms: self.max_skew as f64 / 1e6,
            restarts: merged.restarts,
            strays: merged.strays,
            stale: merged.stale,
            skew: merged.skew,
            class: merged.skew.and_then(|s| receiver_class(s.max_ns, megabits_per_second * 1e6)).map(|c| c.to_string()),
            latency: self.latency.spread(),
            legs,
            ..Report::default()
        };
        match &self.essence {
            Essence::Video { depacketiser, frames } => {
                let frame_rate =
                    (frames.periods > 0 && frames.span > 0).then(|| frames.periods as f64 * 1e9 / frames.span as f64);
                report.video = Some(VideoReport {
                    packets_per_frame: depacketiser.packets_per_frame(),
                    counts: depacketiser.counts(),
                    skipped: frames.skipped,
                    unsent: frames.unsent,
                    irregular: frames.irregular,
                    jumps: frames.jumps,
                    frame_rate,
                });
            }
            Essence::Audio { depacketiser, .. } => {
                report.audio = Some(AudioReport { counts: depacketiser.counts(), peaks: depacketiser.peaks() });
            }
        }
        self.judge(&mut report);
        report
    }

    /// Writes the problems and notes.
    fn judge(&self, r: &mut Report) {
        let (problems, notes) = (&mut r.problems, &mut r.notes);
        let two = r.legs.len() > 1;
        if r.legs.iter().all(|l| l.datagrams == 0) {
            problems.push("nothing arrived".into());
            return;
        }
        for (i, leg) in r.legs.iter().enumerate() {
            let name = format!("leg {} ({})", i + 1, leg.leg);
            let rtp = &leg.rtp;
            if rtp.received == 0 {
                let protection = if two { ", so the stream has no ST 2022-7 protection" } else { "" };
                problems.push(format!("{name} received none of the stream's packets{protection}"));
            } else if two && rtp.lost > 0 {
                notes.push(format!("{name} lost {}", count(rtp.lost, "packet")));
            }
            if rtp.too_late > 0 {
                problems.push(format!(
                    "{name} ran more than {} behind the {}: {} came too late to merge",
                    count(u64::from(self.merger.window()), "packet"),
                    if r.legs.len() > 2 { "others" } else { "other" },
                    count(rtp.too_late, "packet")
                ));
            }
            let seen = [
                (rtp.reordered, "arrived out of order"),
                (rtp.duplicates, "arrived twice"),
                (leg.other_source, "from other sources left out"),
                (leg.other_payload_type, "of other payload types left out"),
                (leg.not_rtp, "that are not the stream's RTP left out"),
            ];
            for (n, what) in seen {
                if n > 0 {
                    let noun = if what.ends_with("left out") { "datagram" } else { "packet" };
                    notes.push(format!("{name}: {} {what}", count(n, noun)));
                }
            }
        }
        if r.lost > 0 {
            let after = if two { " after merging the legs" } else { "" };
            problems.push(format!("{} lost{after}", count(r.lost, "packet")));
        }
        if r.too_late > 0 {
            problems.push(format!(
                "{} came too late to play, after the receiver had waited {} ms for {}",
                count(r.too_late, "packet"),
                r.max_skew_ms,
                if r.too_late == 1 { "it" } else { "them" }
            ));
        }
        if r.restarts > 0 {
            problems.push(format!(
                "the stream restarted {}: a new synchronisation source, or sequence numbers or timestamps that \
                 started again elsewhere",
                times(r.restarts)
            ));
        }
        if r.strays > 0 {
            notes.push(format!("{} fitted neither the stream nor a restart, left out", count(r.strays, "packet")));
        }
        if r.stale > 0 {
            notes.push(format!("{} from before the restart came after it, left out", count(r.stale, "packet")));
        }
        if let Some(video) = &r.video {
            let c = video.counts;
            let incomplete = c.frames - c.whole - c.cut;
            if incomplete > 0 {
                problems.push(format!("{} of {} arrived incomplete", count(incomplete, "frame"), c.frames - c.cut));
            }
            if video.skipped > 0 {
                problems.push(format!("{} never arrived", count(video.skipped, "frame")));
            }
            if video.unsent > 0 {
                let them = if video.unsent == 1 { "it" } else { "them" };
                problems.push(format!(
                    "{} never sent: the RTP timestamps skip {them}, with no packets missing to match, so the sender \
                     left {them} out or its clock stepped",
                    count(video.unsent, "frame")
                ));
            }
            if video.jumps > 0 {
                problems.push(format!(
                    "the RTP timestamps and sequence numbers disagreed {}: the timestamps stood still or stepped \
                     back, or moved on fewer frames than the packets missing",
                    times(video.jumps)
                ));
            }
            if c.malformed > 0 {
                problems
                    .push(format!("{} had payload headers that do not fit the format", count(c.malformed, "packet")));
            }
            if c.late > 0 {
                notes.push(format!(
                    "{} came after {} frame was finished",
                    count(c.late, "packet"),
                    if c.late == 1 { "its" } else { "their" }
                ));
            }
            if video.irregular > 0 {
                notes.push(format!(
                    "{} between RTP timestamps {} not a whole number of frames",
                    count(video.irregular, "step"),
                    if video.irregular == 1 { "is" } else { "are" }
                ));
            }
        }
        if let (Some(audio), Media::Audio(format)) = (&r.audio, &self.description.media) {
            let c = audio.counts;
            let ms = |samples: u64| samples as f64 * 1000.0 / f64::from(format.sample_rate);
            if c.missing > 0 {
                problems.push(format!("{:.3} ms of audio missing, filled with silence", ms(c.missing)));
            }
            if c.unsent > 0 {
                problems.push(format!(
                    "{:.3} ms of audio never sent, filled with silence: the RTP timestamps skip it, with no packets \
                     missing to match",
                    ms(c.unsent)
                ));
            }
            if c.malformed > 0 {
                let does = if c.malformed == 1 { "does" } else { "do" };
                problems.push(format!("{} {does} not hold whole sampling instants", count(c.malformed, "packet")));
            }
            if c.jumps > 0 {
                problems.push(format!(
                    "the RTP timestamps and sequence numbers disagreed {}: the timestamps stood still or stepped \
                     back, or moved on less than the packets missing",
                    times(c.jumps)
                ));
            }
            if c.odd_sized > 0 {
                let differ = if c.odd_sized == 1 { "differs" } else { "differ" };
                notes.push(format!("{} {differ} from the packet time", count(c.odd_sized, "packet")));
            }
        }
    }
}

/// Passes a packet the playout let go to the depacketiser.
fn release(
    essence: &mut Essence,
    latency: &mut Accumulator,
    octets: &mut u64,
    clock_rate: u32,
    packet: Released<'_>,
    sink: &mut impl Sink,
) {
    *octets += packet.data.len() as u64;
    match essence {
        Essence::Video { depacketiser, frames } => {
            let per_frame = depacketiser.packets_per_frame();
            depacketiser.push(packet.at, packet.data, |info, pixels| {
                frames.add(info, per_frame, latency);
                sink.frame(info, pixels);
            });
        }
        Essence::Audio { depacketiser, .. } => {
            if let Some(header) = rtp::read_header(packet.data) {
                latency.add(since_timestamp(header.timestamp, packet.at, clock_rate) / 1000.0);
            }
            depacketiser.push(packet.at, packet.data, packet.missing, |samples| sink.samples(samples));
        }
    }
}

fn times(n: u64) -> String {
    if n == 1 { "once".into() } else { format!("{n} times") }
}

fn count(n: u64, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{n} {noun}s") }
}

/// Nanoseconds from the instant an RTP timestamp names, on a media clock of
/// `clock_rate` Hz counting from the epoch, to `at`: of the instants 2³² ticks apart
/// that it could name, the nearest.
pub fn since_timestamp(timestamp: u32, at: i128, clock_rate: u32) -> f64 {
    let rate = i128::from(clock_rate);
    let ticks = (at * rate).div_euclid(NANOS);
    let full = ticks + i128::from(timestamp.wrapping_sub(ticks as u32) as i32);
    (at * rate - full * NANOS) as f64 / rate as f64
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use st2110_sdp::Rational;

    use super::*;
    use crate::describe::{Clock, Leg};
    use crate::format::{AudioFormat, VideoFormat};
    use crate::send::{Output, Sender};

    const T: i128 = 1_790_510_437 * NANOS;

    #[derive(Default)]
    struct Keep(Vec<(Vec<u8>, i128)>);

    impl Output for Keep {
        fn send(&mut self, packet: &[u8], at: i128) -> std::io::Result<()> {
            self.0.push((packet.to_vec(), at));
            Ok(())
        }
    }

    #[derive(Default)]
    struct Collect {
        frames: Vec<FrameInfo>,
        samples: usize,
    }

    impl Sink for Collect {
        fn frame(&mut self, info: &FrameInfo, _: &[u8]) {
            self.frames.push(*info);
        }

        fn samples(&mut self, samples: &[i32]) {
            self.samples += samples.len();
        }
    }

    fn two_legs(media: Media) -> Description {
        Description {
            name: "test".into(),
            media,
            payload_type: 96,
            legs: vec![
                Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: Some(Ipv4Addr::new(10, 0, 0, 1)) },
                Leg { destination: "239.2.1.1:5004".parse().unwrap(), source: Some(Ipv4Addr::new(10, 0, 1, 1)) },
            ],
            clock: Some(Clock::Traceable),
            ttl: 32,
        }
    }

    #[test]
    fn timestamps_name_instants() {
        // 90 kHz ticks are 11 111.1 ns: 2.5 ticks after tick 0 of this second is 27 777.8 ns.
        let at = T + 27_778;
        let ts = st2110_ptp::epoch::rtp_timestamp(st2110_ptp::PtpTime::from_nanos(T).unwrap(), 90_000);
        assert!((since_timestamp(ts, at, 90_000) - 27_778.0).abs() < 1e-6);
        assert!((since_timestamp(ts.wrapping_add(3), at, 90_000) + 5_555.3).abs() < 0.1);
    }

    #[test]
    fn two_legs_that_each_lose_packets_make_one_whole_stream() {
        let format = VideoFormat::new(640, 360, Rational::new(50, 1).unwrap());
        let d = two_legs(Media::Video(format.clone()));
        let mut sender = Sender::new(&d, 1000, -18.0, 7, 65_000).unwrap();
        let mut out = Keep::default();
        sender.run(&mut out, T, T + 5 * 20_000_000).unwrap();
        let mut session = Session::new(&d).unwrap();
        let mut sink = Collect::default();
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 1, 1));
        for (i, (packet, at)) in out.0.iter().enumerate() {
            if i % 50 != 3 {
                session.push(0, a, *at + 20_000, packet, &mut sink);
            }
            if i % 70 != 5 {
                session.push(1, b, *at + 60_000, packet, &mut sink);
            }
        }
        // A stranger on leg 2, and a packet from elsewhere.
        session.push(1, a, T, &out.0[0].0, &mut sink);
        session.finish(T + 5 * 20_000_000, &mut sink);
        let r = session.report();
        assert_eq!(sink.frames.len(), 5);
        assert!(sink.frames.iter().all(|f| f.whole), "{:?}", sink.frames);
        assert_eq!((r.lost, r.problems.len()), (0, 0), "{r:?}");
        let video = r.video.unwrap();
        assert_eq!((video.counts.frames, video.counts.whole, video.skipped, video.irregular), (5, 5, 0, 0));
        assert!((video.frame_rate.unwrap() - 50.0).abs() < 1e-6);
        assert_eq!(r.legs[1].other_source, 1);
        assert!(r.legs[0].rtp.lost > 0 && r.legs[1].rtp.lost > 0);
        let skew = r.skew.unwrap();
        assert_eq!(skew.max_ns, 40_000);
        assert_eq!(r.class.as_deref(), Some("D"));
        // The first packet goes TRO − lead after the alignment point, and arrives 20 µs later.
        let schedule = sender.schedule().unwrap();
        let latency = r.latency.unwrap();
        let expected = (schedule.send_offset(0) + 20_000) as f64 / 1000.0;
        assert!((latency.min - expected).abs() < 0.01 && (latency.max - expected).abs() < 0.01, "{latency:?}");
        assert_eq!(r.notes.len(), 3, "{:?}", r.notes);
    }

    #[test]
    fn a_lost_frame_and_audio_gaps_are_problems() {
        let format = VideoFormat::new(320, 180, Rational::new(25, 1).unwrap());
        let mut d = two_legs(Media::Video(format.clone()));
        d.legs.truncate(1);
        let packets = Arc::new(Layout::new(&format).unwrap()).packets();
        let mut out = Keep::default();
        Sender::new(&d, 1000, -18.0, 7, 0).unwrap().run(&mut out, T, T + 4 * 40_000_000).unwrap();
        let mut session = Session::new(&d).unwrap();
        // Frame 2 goes missing whole.
        for (packet, at) in out.0.iter().enumerate().filter(|(i, _)| i / packets != 1).map(|(_, p)| p) {
            session.push(0, Ipv4Addr::new(10, 0, 0, 1), *at, packet, &mut ());
        }
        session.finish(T + 4 * 40_000_000, &mut ());
        let r = session.report();
        let video = r.video.unwrap();
        assert_eq!((video.skipped, video.counts.frames, video.counts.whole), (1, 3, 3));
        assert_eq!((r.lost, video.counts.missing, video.packets_per_frame), (packets as u64, 0, Some(packets as u32)));
        assert_eq!(r.problems, [format!("{packets} packets lost"), "1 frame never arrived".to_string()]);

        let mut d = two_legs(Media::Audio(AudioFormat::new(2)));
        d.legs.truncate(1);
        let mut out = Keep::default();
        Sender::new(&d, 1000, -18.0, 7, 0).unwrap().run(&mut out, T, T + 10_000_000).unwrap();
        let mut session = Session::new(&d).unwrap();
        let mut sink = Collect::default();
        for (i, (packet, at)) in out.0.iter().enumerate() {
            if i != 4 {
                session.push(0, Ipv4Addr::new(10, 0, 0, 1), *at, packet, &mut sink);
            }
        }
        // The packets after the gap wait for it, until receiving stops.
        assert_eq!(sink.samples, 4 * 96);
        session.finish(T + 10_000_000, &mut sink);
        let r = session.report();
        assert_eq!(sink.samples, 10 * 96);
        let audio = r.audio.unwrap();
        assert_eq!((audio.counts.missing, audio.counts.packets), (48, 9));
        assert_eq!(r.problems, ["1 packet lost", "1.000 ms of audio missing, filled with silence"]);
        let latency = r.latency.unwrap();
        assert!((latency.min - 1000.0).abs() < 0.01 && (latency.max - 1000.0).abs() < 0.01, "{latency:?}");
        assert!(audio.peaks.iter().all(|p| p.is_some_and(|db| (db + 18.0).abs() < 0.01)));
    }
}
