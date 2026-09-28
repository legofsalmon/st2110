//! Sending a stream: test signals, or pictures from elsewhere, cut into packets, each
//! sent at its time.
//!
//! Frames and packets line up with the SMPTE Epoch as ST 2059-1 and ST 2110-10 ask:
//! video frame `n` has its alignment point at n ÷ rate seconds of TAI and the RTP
//! timestamp of that instant, and audio packets start on whole packet times.
//!
//! [`Sender`] sends colour bars or a tone. [`VideoSender`] sends the frames a
//! [`FrameSource`] gives it, such as a renderer's pictures packed with
//! [`crate::pixels::Converter`].

use std::io;
use std::sync::Arc;

use st2110_ptp::epoch;
use st2110_sdp::video::tro_default_progressive;

use crate::audio::AudioPacketiser;
use crate::describe::{Description, Media};
use crate::format::{SenderType, VideoFormat};
use crate::pattern::{Bars, Tone};
use crate::video::{Layout, Packetiser};

const NANOS: i128 = 1_000_000_000;

/// Where packets go: sockets, which wait for each packet's time, or a capture file,
/// which stamps each packet with it.
pub trait Output {
    /// Sends one packet at `at`, in nanoseconds of TAI since the epoch.
    fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()>;

    /// The time now, in nanoseconds of TAI, for an output that waits; `None` for one that
    /// does not, which is never behind.
    fn now(&self) -> Option<i128> {
        None
    }
}

/// When a video sender sends each packet of a frame: the ST 2110-21 read schedule, a
/// little early.
///
/// The virtual receiver reads packet j at TRO + j × TRS after the frame's alignment
/// point, with the default read offset and, for a narrow gapped sender, packets spread
/// over the active part of the frame only. Each packet is sent `lead` before its read:
/// half the read offset, so the first packet still comes after the alignment point its
/// timestamp names, and no more than half the virtual receiver's buffer (VRXFULL).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Schedule {
    /// TRO in nanoseconds.
    pub read_offset: f64,
    /// TRS in nanoseconds.
    pub read_spacing: f64,
    /// How long before its read each packet is sent, in nanoseconds.
    pub lead: f64,
}

impl Schedule {
    /// The schedule for a format sent in `packets` packets a frame.
    pub fn new(format: &VideoFormat, packets: usize) -> Self {
        let rate = format.rate.to_f64();
        let frame = 1e9 / rate;
        let read_offset = tro_default_progressive(format.height, format.rate) * 1e9;
        // RACTIVE is 1080/1125 for progressive video (ST 2110-21:2022 §6.3.2).
        let active = if format.sender_type.gapped() { 1080.0 / 1125.0 } else { 1.0 };
        let read_spacing = frame * active / packets as f64;
        let np_rate = packets as f64 * rate;
        // ST 2110-21:2022 §6.6.2, with MAXUDP of 1500.
        let vrx_full = if format.sender_type == SenderType::Wide {
            (np_rate / 300.0).floor().max(720.0)
        } else {
            (np_rate / 27_000.0).floor().max(8.0)
        };
        let lead = (read_offset / 2.0).min(vrx_full / 2.0 * read_spacing);
        Self { read_offset, read_spacing, lead }
    }

    /// When to send packet `index`, in nanoseconds after the frame's alignment point.
    pub fn send_offset(&self, index: usize) -> i128 {
        (self.read_offset + index as f64 * self.read_spacing - self.lead).round() as i128
    }
}

/// The rate from which ST 2110-21:2022 §7.1 defines no wide sender, in packets a second.
pub const WIDE_LIMIT: u64 = 900_000;

/// Whether `packets` a frame of a format come to fewer than [`WIDE_LIMIT`] a second.
fn below_wide_limit(format: &VideoFormat, packets: usize) -> bool {
    let (num, den) = (u128::from(format.rate.numerator()), u128::from(format.rate.denominator()));
    packets as u128 * num < u128::from(WIDE_LIMIT) * den
}

/// The sender type a format goes out as unless another is asked for: wide, which pacing
/// on ordinary sockets can hope to keep to, below [`WIDE_LIMIT`] packets a second, and
/// narrow linear from there, where ST 2110-21 defines no wide sender.
pub fn default_sender_type(format: &VideoFormat) -> Result<SenderType, String> {
    let packets = Layout::new(format)?.packets();
    Ok(if below_wide_limit(format, packets) { SenderType::Wide } else { SenderType::NarrowLinear })
}

/// What a sender sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SendCounts {
    /// Video frames, or audio packet times.
    pub frames: u64,
    /// Packets, on each leg.
    pub packets: u64,
    /// Octets of RTP, on each leg.
    pub octets: u64,
    /// Frames left out because their time had passed before they could be sent.
    pub skipped: u64,
}

/// Gives a [`VideoSender`] its frames.
pub trait FrameSource {
    /// Frame `n`, counted in frame periods from the epoch, as a frame of pixel groups of
    /// [`VideoFormat::frame_bytes`] octets; `None` stops the sender.
    fn frame(&mut self, n: u64) -> Option<&[u8]>;
}

impl FrameSource for Bars {
    fn frame(&mut self, n: u64) -> Option<&[u8]> {
        Some(Bars::frame(self, n))
    }
}

/// Sends a video stream: the frames a [`FrameSource`] gives, each cut into packets and
/// each packet sent at its time.
///
/// ```
/// use st2110_media::describe::{Clock, Description, Leg, Media};
/// use st2110_media::format::VideoFormat;
/// use st2110_media::pixels::{Converter, Order};
/// use st2110_media::send::{FrameSource, Output, VideoSender};
///
/// /// One picture, packed once, sent as every frame; frames 40 ms long stop it after two.
/// struct Still(Vec<u8>, u32);
///
/// impl FrameSource for Still {
///     fn frame(&mut self, _n: u64) -> Option<&[u8]> {
///         self.1 += 1;
///         (self.1 <= 2).then_some(&self.0[..])
///     }
/// }
///
/// struct Count(usize);
///
/// impl Output for Count {
///     fn send(&mut self, _packet: &[u8], _at: i128) -> std::io::Result<()> {
///         self.0 += 1;
///         Ok(())
///     }
/// }
///
/// let format = VideoFormat::from_name("1280x720p25").unwrap();
/// // A picture as a GPU reads it back: B', G', R' and alpha, rows padded to 256 octets.
/// let stride = 5120;
/// let picture = vec![128; stride * 720];
/// let mut frame = vec![0; format.frame_bytes()];
/// Converter::new(&format).unwrap().pack_frame(&picture, stride, Order::BGRA, &mut frame);
///
/// let stream = Description {
///     name: "Still".into(),
///     media: Media::Video(format),
///     payload_type: 96,
///     legs: vec![Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: None }],
///     clock: Some(Clock::Traceable),
///     ttl: 32,
/// };
/// let mut sender = VideoSender::new(&stream, 0x1234, 0).unwrap();
/// let start = 1_790_510_437 * 1_000_000_000;
/// let sent = sender.run(&mut Count(0), start, i128::MAX, &mut Still(frame, 0)).unwrap();
/// assert_eq!((sent.frames, sent.packets), (2, 2 * sender.packets() as u64));
/// ```
pub struct VideoSender {
    packetiser: Packetiser,
    schedule: Schedule,
    format: VideoFormat,
    buffer: Vec<u8>,
}

impl VideoSender {
    /// A sender of the video stream a description gives. `ssrc` and `first_sequence`
    /// start the RTP header; RFC 3550 asks for random ones.
    pub fn new(description: &Description, ssrc: u32, first_sequence: u32) -> Result<Self, String> {
        description.check()?;
        let Media::Video(format) = &description.media else {
            return Err(format!("{} is not video", description.media));
        };
        let layout = Arc::new(Layout::new(format)?);
        if format.sender_type == SenderType::Wide && !below_wide_limit(format, layout.packets()) {
            return Err(format!(
                "ST 2110-21 defines no wide sender (2110TPW) at {:.0} packets a second, {WIDE_LIMIT} or \
                 more: send {format} as 2110TPN or 2110TPNL",
                layout.packets() as f64 * format.rate.to_f64()
            ));
        }
        Ok(Self {
            schedule: Schedule::new(format, layout.packets()),
            packetiser: Packetiser::new(layout, description.payload_type, ssrc, first_sequence),
            format: format.clone(),
            buffer: Vec::with_capacity(1500),
        })
    }

    /// The format it sends.
    pub fn format(&self) -> &VideoFormat {
        &self.format
    }

    /// The schedule its packets follow.
    pub fn schedule(&self) -> Schedule {
        self.schedule
    }

    /// Packets a frame.
    pub fn packets(&self) -> usize {
        self.packetiser.layout().packets()
    }

    /// Sends frame after frame, from the first whose alignment point is at `start` or
    /// after, until the one at `end` or until `frames` gives none, in nanoseconds of TAI.
    /// A frame whose time has passed before it can be sent is left out, and `frames` is
    /// not asked for it.
    pub fn run(
        &mut self,
        output: &mut dyn Output,
        start: i128,
        end: i128,
        frames: &mut dyn FrameSource,
    ) -> io::Result<SendCounts> {
        let mut counts = SendCounts::default();
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{what} is out of range"));
        let rate = self.format.rate;
        let (packets, octets) = (self.packets(), self.format.frame_bytes());
        let start = st2110_ptp::PtpTime::from_nanos(start - 1).ok_or_else(|| bad("the start"))?;
        let (mut n, _) = epoch::next_alignment(start, epoch::Signal::Video(rate)).ok_or_else(|| bad("the start"))?;
        let frame_ns = 1e9 / rate.to_f64();
        loop {
            let t0 = epoch::period_start(n, rate).ok_or_else(|| bad("the frame"))?.nanos();
            if t0 >= end {
                break;
            }
            if output.now().is_some_and(|now| (now - t0) as f64 > frame_ns) {
                counts.skipped += 1;
                n += 1;
                continue;
            }
            let timestamp = epoch::frame_rtp_timestamp(n, rate, 90_000).ok_or_else(|| bad("the frame"))?;
            let Some(frame) = frames.frame(n as u64) else { break };
            if frame.len() != octets {
                let e = format!("{} octets is not a frame of {} of {octets}", frame.len(), self.format);
                return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
            }
            for index in 0..packets {
                self.packetiser.packet(frame, index, timestamp, &mut self.buffer);
                output.send(&self.buffer, t0 + self.schedule.send_offset(index))?;
                counts.octets += self.buffer.len() as u64;
            }
            counts.frames += 1;
            counts.packets += packets as u64;
            n += 1;
        }
        Ok(counts)
    }
}

enum Signal {
    Video { bars: Bars, sender: Box<VideoSender> },
    Audio { tone: Tone, packetiser: AudioPacketiser, per_packet: u32, rate: u32, samples: Vec<i32> },
}

/// Sends colour bars or a tone as a stream.
pub struct Sender {
    signal: Signal,
    buffer: Vec<u8>,
}

impl Sender {
    /// A sender of the stream a description gives: colour bars for video, and for
    /// audio a tone of `tone` Hz at `level` dBFS. `ssrc` and `first_sequence` start
    /// the RTP header; RFC 3550 asks for random ones.
    pub fn new(
        description: &Description,
        tone: u32,
        level: f64,
        ssrc: u32,
        first_sequence: u32,
    ) -> Result<Self, String> {
        description.check()?;
        let pt = description.payload_type;
        let signal = match &description.media {
            Media::Video(format) => Signal::Video {
                sender: Box::new(VideoSender::new(description, ssrc, first_sequence)?),
                bars: Bars::new(format)?,
            },
            Media::Audio(format) => Signal::Audio {
                tone: Tone::new(format, tone, level)?,
                packetiser: AudioPacketiser::new(format, pt, ssrc, first_sequence as u16)?,
                per_packet: format.samples_per_packet,
                rate: format.sample_rate,
                samples: Vec::new(),
            },
        };
        Ok(Self { signal, buffer: Vec::with_capacity(1500) })
    }

    /// The schedule video packets follow; `None` for audio.
    pub fn schedule(&self) -> Option<Schedule> {
        match &self.signal {
            Signal::Video { sender, .. } => Some(sender.schedule()),
            Signal::Audio { .. } => None,
        }
    }

    /// Sends every video frame, or audio packet, that starts at `start` or after and
    /// before `end`, in nanoseconds of TAI. Audio packets go out when their last sample
    /// is due, one packet time after the first.
    pub fn run(&mut self, output: &mut dyn Output, start: i128, end: i128) -> io::Result<SendCounts> {
        let (tone, packetiser, per, rate, samples) = match &mut self.signal {
            Signal::Video { bars, sender } => return sender.run(output, start, end, bars),
            Signal::Audio { tone, packetiser, per_packet, rate, samples } => {
                (tone, packetiser, i128::from(*per_packet), i128::from(*rate), samples)
            }
        };
        let mut counts = SendCounts::default();
        // The first packet time that starts at `start` or after.
        let mut k = (start * rate).div_euclid(NANOS * per) * per;
        if k * NANOS < start * rate {
            k += per;
        }
        loop {
            let first = k * NANOS / rate + i128::from(k * NANOS % rate != 0);
            if first >= end {
                break;
            }
            let due = (k + per) * NANOS / rate;
            if output.now().is_some_and(|now| now - due > NANOS / 10) {
                counts.skipped += 1;
                k += per;
                continue;
            }
            tone.fill(k as u64, per as usize, samples);
            packetiser.packet(samples, k as u32, &mut self.buffer);
            output.send(&self.buffer, due)?;
            counts.frames += 1;
            counts.packets += 1;
            counts.octets += self.buffer.len() as u64;
            k += per;
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use st2110_sdp::Rational;

    use super::*;
    use crate::describe::{Clock, Leg};
    use crate::format::{AudioFormat, SenderType};

    /// Keeps what it is sent, with the time.
    #[derive(Default)]
    struct Keep(Vec<(Vec<u8>, i128)>);

    impl Output for Keep {
        fn send(&mut self, packet: &[u8], at: i128) -> io::Result<()> {
            self.0.push((packet.to_vec(), at));
            Ok(())
        }
    }

    fn description(media: Media) -> Description {
        Description {
            name: "test".into(),
            media,
            payload_type: 96,
            legs: vec![Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: Some(Ipv4Addr::LOCALHOST) }],
            clock: Some(Clock::Traceable),
            ttl: 32,
        }
    }

    /// 2026-09-27 12:00:00 UTC, in TAI.
    const T: i128 = 1_790_510_437 * NANOS;

    #[test]
    fn schedules() {
        let mut f = VideoFormat::new(1920, 1080, Rational::new(50, 1).unwrap());
        let s = Schedule::new(&f, 4320);
        // TRO = 43/1125 × 20 ms; TRS = 20 ms ÷ 4320; lead = TRO ÷ 2.
        assert!((s.read_offset - 764_444.4).abs() < 0.1, "{s:?}");
        assert!((s.read_spacing - 4629.63).abs() < 0.01, "{s:?}");
        assert!((s.lead - s.read_offset / 2.0).abs() < 1e-6);
        assert_eq!(s.send_offset(0), 382_222);
        f.sender_type = SenderType::Narrow;
        let s = Schedule::new(&f, 4320);
        // Gapped: TRS = 20 ms × 1080/1125 ÷ 4320; VRXFULL is 8, so a lead of 4 × TRS.
        assert!((s.read_spacing - 4444.44).abs() < 0.01, "{s:?}");
        assert!((s.lead - 4.0 * s.read_spacing).abs() < 1e-6, "{s:?}");
    }

    #[test]
    fn no_wide_sender_from_900_000_packets_a_second() {
        let mut f = VideoFormat::from_name("2160p59.94").unwrap();
        assert_eq!(default_sender_type(&f), Ok(SenderType::NarrowLinear));
        let e = Sender::new(&description(Media::Video(f.clone())), 1000, -18.0, 1, 0).err().unwrap();
        assert!(
            e.contains("no wide sender (2110TPW) at 906294 packets a second") && e.contains("as 2110TPN or 2110TPNL"),
            "{e}"
        );
        f.sender_type = SenderType::NarrowLinear;
        assert!(Sender::new(&description(Media::Video(f)), 1000, -18.0, 1, 0).is_ok());
        assert_eq!(default_sender_type(&VideoFormat::from_name("2160p50").unwrap()), Ok(SenderType::Wide));
    }

    #[test]
    fn video_frames_start_on_the_epoch() {
        let format = VideoFormat::new(320, 180, Rational::new(60_000, 1001).unwrap());
        let mut sender = Sender::new(&description(Media::Video(format.clone())), 1000, -18.0, 1, 0).unwrap();
        let mut out = Keep::default();
        // Three frames from T; 1/59.94 s is 16 683 333.3 ns.
        let counts = sender.run(&mut out, T, T + 3 * 16_683_334).unwrap();
        let packets = Layout::new(&format).unwrap().packets() as u64;
        assert_eq!((counts.frames, counts.packets, counts.skipped), (3, 3 * packets, 0));
        let first = st2110_pcap::rtp::header(&out.0[0].0, true).unwrap();
        let n = (T * 60_000 + 1001 * NANOS - 1) / (1001 * NANOS);
        assert_eq!(first.timestamp, epoch::frame_rtp_timestamp(n, format.rate, 90_000).unwrap());
        let t0 = epoch::period_start(n, format.rate).unwrap().nanos();
        assert!(t0 >= T && t0 - T < 16_683_334);
        assert_eq!(out.0[0].1, t0 + sender.schedule().unwrap().send_offset(0));
        let next = st2110_pcap::rtp::header(&out.0[packets as usize].0, true).unwrap();
        assert!([1501, 1502].contains(&next.timestamp.wrapping_sub(first.timestamp)));
        assert!(out.0.windows(2).all(|w| w[0].1 < w[1].1));
    }

    /// Gives each frame filled with its own number, `count` of them, and notes which.
    struct Numbered {
        frame: Vec<u8>,
        count: usize,
        asked: Vec<u64>,
    }

    impl FrameSource for Numbered {
        fn frame(&mut self, n: u64) -> Option<&[u8]> {
            if self.asked.len() == self.count {
                return None;
            }
            self.asked.push(n);
            self.frame.fill(n as u8);
            Some(&self.frame)
        }
    }

    #[test]
    fn sends_the_frames_a_source_gives_until_it_gives_none() {
        let format = VideoFormat::new(320, 180, Rational::new(50, 1).unwrap());
        let mut sender = VideoSender::new(&description(Media::Video(format.clone())), 1, 0).unwrap();
        let mut frames = Numbered { frame: vec![0; format.frame_bytes()], count: 3, asked: Vec::new() };
        let mut out = Keep::default();
        let counts = sender.run(&mut out, T + 1, i128::MAX, &mut frames).unwrap();
        // T is on a 50 Hz alignment point, and the first frame is the one after it.
        let n = (T / (NANOS / 50)) as u64 + 1;
        assert_eq!(frames.asked, [n, n + 1, n + 2]);
        assert_eq!((counts.frames, counts.packets, counts.skipped), (3, 3 * sender.packets() as u64, 0));

        // Each frame arrives as it was given, with its own timestamp.
        let mut depacketiser = crate::video::Depacketiser::new(&format).unwrap();
        let mut got = Vec::new();
        let mut done = |info: &crate::video::FrameInfo, frame: &[u8]| got.push((info.timestamp, frame.to_vec()));
        for (packet, at) in &out.0 {
            depacketiser.push(*at, packet, &mut done);
        }
        depacketiser.flush(None, &mut done);
        let expected: Vec<_> = (n..n + 3)
            .map(|n| {
                (
                    epoch::frame_rtp_timestamp(n.into(), format.rate, 90_000).unwrap(),
                    vec![n as u8; format.frame_bytes()],
                )
            })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn frames_whose_time_has_passed_are_left_out_unasked() {
        /// An output whose clock stands two and a half frames after `T`.
        struct Behind(usize);

        impl Output for Behind {
            fn send(&mut self, _packet: &[u8], _at: i128) -> io::Result<()> {
                self.0 += 1;
                Ok(())
            }

            fn now(&self) -> Option<i128> {
                Some(T + 50_000_000)
            }
        }

        let format = VideoFormat::new(320, 180, Rational::new(50, 1).unwrap());
        let mut sender = VideoSender::new(&description(Media::Video(format.clone())), 1, 0).unwrap();
        let mut frames = Numbered { frame: vec![0; format.frame_bytes()], count: 2, asked: Vec::new() };
        let counts = sender.run(&mut Behind(0), T, i128::MAX, &mut frames).unwrap();
        // Frames at T and T + 20 ms are over by T + 50 ms; the one at T + 40 ms is not.
        let n = (T / (NANOS / 50)) as u64;
        assert_eq!(frames.asked, [n + 2, n + 3]);
        assert_eq!((counts.frames, counts.skipped), (2, 2));
    }

    #[test]
    fn a_frame_of_the_wrong_size_is_refused() {
        struct Short;

        impl FrameSource for Short {
            fn frame(&mut self, _n: u64) -> Option<&[u8]> {
                Some(&[0; 100])
            }
        }

        let format = VideoFormat::new(320, 180, Rational::new(50, 1).unwrap());
        let mut sender = VideoSender::new(&description(Media::Video(format)), 1, 0).unwrap();
        let e = sender.run(&mut Keep::default(), T, i128::MAX, &mut Short).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(e.to_string(), "100 octets is not a frame of 320x180p50 YCbCr-4:2:2 10-bit of 144000");
        let audio = VideoSender::new(&description(Media::Audio(AudioFormat::new(2))), 1, 0).err().unwrap();
        assert!(audio.ends_with("is not video"), "{audio}");
    }

    #[test]
    fn audio_packets_start_on_whole_packet_times() {
        let format = AudioFormat::new(2);
        let mut sender = Sender::new(&description(Media::Audio(format)), 1000, -18.0, 1, 65_535).unwrap();
        let mut out = Keep::default();
        let counts = sender.run(&mut out, T + 1, T + 5 * 1_000_000).unwrap();
        // The packet at T starts before T + 1 ns, so four of them.
        assert_eq!((counts.frames, counts.packets), (4, 4));
        let h = st2110_pcap::rtp::header(&out.0[0].0, true).unwrap();
        assert_eq!(h.timestamp, epoch::rtp_timestamp(st2110_ptp::PtpTime::from_nanos(T + 1_000_000).unwrap(), 48_000));
        assert_eq!(out.0[0].1, T + 2_000_000);
        assert_eq!(st2110_pcap::rtp::header(&out.0[1].0, true).unwrap().sequence, 0);
    }
}
