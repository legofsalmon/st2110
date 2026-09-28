//! Receiving a stream: datagrams from each leg, merged, checked and put back together.

use std::net::Ipv4Addr;

use crate::audio::{AudioCounts, AudioDepacketiser};
use crate::describe::{Description, Media};
use crate::merge::{Extender, LegCounts, Merger, Skew, Verdict, receiver_class};
use crate::rtp;
use crate::video::{Depacketiser, FrameInfo, Layout, VideoCounts};

const NANOS: i128 = 1_000_000_000;

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
    /// Packets each frame should have.
    pub packets_per_frame: usize,
    /// Frames, packets and faults the depacketiser counted.
    pub counts: VideoCounts,
    /// Frames that never arrived at all: steps of more than one frame between the RTP
    /// timestamps of the frames either side.
    pub skipped: u64,
    /// Steps between RTP timestamps that are not a whole number of frames.
    pub irregular: u64,
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
    /// The synchronisation source of the first packet.
    pub ssrc: Option<u32>,
    /// Times the synchronisation source changed.
    pub ssrc_changes: u64,
    /// Packets passed on after merging: the first copy of each.
    pub passed: u64,
    /// Packets no leg delivered in time.
    pub lost: u64,
    /// Copies too late for the merge window.
    pub too_late: u64,
    /// Jumps in the sequence numbers, where the sender restarted.
    pub jumps: u64,
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
    last_timestamp: Option<u32>,
    /// When the first packets of the first and last frames that receiving did not cut
    /// off arrived, and how many such frames there were.
    first_arrival: Option<i128>,
    last_arrival: i128,
    timed: u64,
    skipped: u64,
    irregular: u64,
}

impl Frames {
    fn add(&mut self, info: &FrameInfo, latency: &mut Accumulator) {
        // A frame cut off at the start did not arrive from its first packet.
        if !info.cut {
            latency.add(since_timestamp(info.timestamp, info.first_arrival, 90_000) / 1000.0);
            self.first_arrival.get_or_insert(info.first_arrival);
            self.last_arrival = info.first_arrival;
            self.timed += 1;
        }
        if let Some(last) = self.last_timestamp {
            let step = f64::from(info.timestamp.wrapping_sub(last));
            let frames = (step / self.step).round();
            if (step - frames * self.step).abs() > 1.5 || frames < 1.0 {
                self.irregular += 1;
            } else {
                self.skipped += frames as u64 - 1;
            }
        }
        self.last_timestamp = Some(info.timestamp);
    }
}

enum Essence {
    Video { depacketiser: Box<Depacketiser>, packets: usize, frames: Frames },
    Audio { depacketiser: AudioDepacketiser, extender: Extender },
}

/// Receives one stream: takes the datagrams that arrive on each leg, merges the legs,
/// puts frames or samples back together for a [`Sink`], and reports what it found.
pub struct Session {
    description: Description,
    legs: Vec<LegState>,
    merger: Merger,
    essence: Essence,
    ssrc: Option<u32>,
    last_ssrc: Option<u32>,
    ssrc_changes: u64,
    first: Option<i128>,
    last: i128,
    passed_octets: u64,
    latency: Accumulator,
}

impl Session {
    /// A receiver of the stream a description gives.
    pub fn new(description: &Description) -> Result<Self, String> {
        description.check()?;
        let (essence, rate) = match &description.media {
            Media::Video(format) => {
                let packets = Layout::new(format)?.packets();
                let frames = Frames { step: 90_000.0 / format.rate.to_f64(), ..Frames::default() };
                let depacketiser = Box::new(Depacketiser::new(format)?);
                (Essence::Video { depacketiser, packets, frames }, packets as f64 * format.rate.to_f64())
            }
            Media::Audio(format) => (
                Essence::Audio { depacketiser: AudioDepacketiser::new(format)?, extender: Extender::default() },
                1e6 / f64::from(format.packet_time_us),
            ),
        };
        Ok(Self {
            legs: vec![LegState::default(); description.legs.len()],
            merger: Merger::new(description.legs.len(), Merger::window_for(rate)),
            description: description.clone(),
            essence,
            ssrc: None,
            last_ssrc: None,
            ssrc_changes: 0,
            first: None,
            last: 0,
            passed_octets: 0,
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
        let sequence = match &mut self.essence {
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
        self.ssrc.get_or_insert(header.ssrc);
        if self.last_ssrc.is_some_and(|last| last != header.ssrc) {
            self.ssrc_changes += 1;
        }
        self.last_ssrc = Some(header.ssrc);
        if self.merger.push(leg, sequence, at) != Verdict::First {
            return;
        }
        self.passed_octets += datagram.len() as u64;
        match &mut self.essence {
            Essence::Video { depacketiser, frames, .. } => {
                let latency = &mut self.latency;
                depacketiser.push(at, datagram, |info, pixels| {
                    frames.add(info, latency);
                    sink.frame(info, pixels);
                });
            }
            Essence::Audio { depacketiser, .. } => {
                let rate = self.description.media.clock_rate();
                self.latency.add(since_timestamp(header.timestamp, at, rate) / 1000.0);
                depacketiser.push(datagram, |samples| sink.samples(samples));
            }
        }
    }

    /// Finishes the frame being put together, if there is one: call it when no more
    /// packets will come.
    pub fn finish(&mut self, sink: &mut impl Sink) {
        if let Essence::Video { depacketiser, frames, .. } = &mut self.essence {
            let latency = &mut self.latency;
            depacketiser.flush(|info, pixels| {
                frames.add(info, latency);
                sink.frame(info, pixels);
            });
        }
    }

    /// The last video frame that arrived whole.
    pub fn last_whole_frame(&self) -> Option<&[u8]> {
        match &self.essence {
            Essence::Video { depacketiser, .. } => depacketiser.last_whole(),
            Essence::Audio { .. } => None,
        }
    }

    /// What it found so far.
    pub fn report(&self) -> Report {
        let merged = self.merger.counts();
        let seconds = self.first.map_or(0.0, |first| (self.last - first) as f64 / 1e9);
        let megabits_per_second = if seconds > 0.0 { self.passed_octets as f64 * 8.0 / seconds / 1e6 } else { 0.0 };
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
            ssrc: self.ssrc,
            ssrc_changes: self.ssrc_changes,
            passed: merged.passed,
            lost: merged.lost,
            too_late: merged.too_late,
            jumps: merged.jumps,
            skew: merged.skew,
            class: merged.skew.and_then(|s| receiver_class(s.max_ns, megabits_per_second * 1e6)).map(|c| c.to_string()),
            latency: self.latency.spread(),
            legs,
            ..Report::default()
        };
        match &self.essence {
            Essence::Video { depacketiser, packets, frames } => {
                let frame_rate = frames
                    .first_arrival
                    .filter(|&first| frames.timed > 1 && frames.last_arrival > first)
                    .map(|first| (frames.timed - 1) as f64 * 1e9 / (frames.last_arrival - first) as f64);
                report.video = Some(VideoReport {
                    packets_per_frame: *packets,
                    counts: depacketiser.counts(),
                    skipped: frames.skipped,
                    irregular: frames.irregular,
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
            if leg.rtp.received == 0 {
                problems
                    .push(format!("{name} received none of the stream's packets, so it has no ST 2022-7 protection"));
            } else if two && leg.rtp.lost > 0 {
                notes.push(format!("{name} lost {}", count(leg.rtp.lost, "packet")));
            }
            let left_out = [
                (leg.other_source, "from other sources"),
                (leg.other_payload_type, "of other payload types"),
                (leg.not_rtp, "that are not the stream's RTP"),
            ];
            for (n, what) in left_out {
                if n > 0 {
                    notes.push(format!("{name}: {} {what} left out", count(n, "datagram")));
                }
            }
        }
        if r.lost > 0 {
            let after = if two { " after merging the legs" } else { "" };
            problems.push(format!("{} lost{after}", count(r.lost, "packet")));
        }
        if r.too_late > 0 {
            notes.push(format!("{} came too late to merge", count(r.too_late, "packet")));
        }
        if r.jumps > 0 {
            notes.push(format!("the sequence numbers jumped {}: the sender restarted", count(r.jumps, "time")));
        }
        if r.ssrc_changes > 0 {
            notes.push(format!("the synchronisation source changed {}", count(r.ssrc_changes, "time")));
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
            if c.malformed > 0 {
                problems
                    .push(format!("{} had payload headers that do not fit the format", count(c.malformed, "packet")));
            }
            if c.late > 0 {
                notes.push(format!("{} came after their frame was finished", count(c.late, "packet")));
            }
            if video.irregular > 0 {
                notes.push(format!("{} between RTP timestamps are not whole frames", count(video.irregular, "step")));
            }
        }
        if let (Some(audio), Media::Audio(format)) = (&r.audio, &self.description.media) {
            let c = audio.counts;
            if c.missing > 0 {
                let ms = c.missing as f64 * 1000.0 / f64::from(format.sample_rate);
                problems.push(format!("{ms:.3} ms of audio missing, filled with silence"));
            }
            if c.malformed > 0 {
                problems.push(format!("{} are not whole sampling instants", count(c.malformed, "packet")));
            }
            if c.late > 0 {
                notes.push(format!("{} came after later ones had been played", count(c.late, "packet")));
            }
            if c.odd_sized > 0 {
                notes.push(format!("{} differ from the packet time", count(c.odd_sized, "packet")));
            }
            if c.jumps > 0 {
                notes.push(format!("the RTP timestamps jumped {}", count(c.jumps, "time")));
            }
        }
    }
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
        session.finish(&mut sink);
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
        session.finish(&mut ());
        let r = session.report();
        let video = r.video.unwrap();
        assert_eq!((video.skipped, video.counts.frames, video.counts.whole), (1, 3, 3));
        assert_eq!((r.lost, video.counts.missing), (packets as u64, packets as u64));
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
