//! What an analysis found: the capture, its flows, its PTP traffic and every finding.

use st2110_sdp::{Essence, Rule, Severity};

use crate::stats::Stats;

/// What [`analyse`](crate::analyse) found in a capture.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Report {
    /// The file and what it held.
    pub capture: Capture,
    /// Which clock the capture's timestamps count, and how that was decided.
    pub timescale: TimescaleReport,
    /// Each RTP flow, in order of its first packet.
    pub flows: Vec<FlowReport>,
    /// The PTP messages.
    pub ptp: PtpReport,
    /// Streams in the SDP files that no flow in the capture matched.
    pub missing: Vec<String>,
    /// Every finding: the capture's, then each flow's in turn, then PTP's.
    pub findings: Vec<Finding>,
}

impl Report {
    /// The number of findings of one severity.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }

    /// True if any finding is an error.
    pub fn has_errors(&self) -> bool {
        self.count(Severity::Error) > 0
    }
}

/// The capture file and what it held.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Capture {
    /// The file format, such as `pcapng`.
    pub format: String,
    /// Frames read.
    pub frames: u64,
    /// When the first frame was captured, by the capturing clock: seconds and
    /// nanoseconds since 1970, such as `1790510437.123456789`.
    pub start: Option<String>,
    /// Seconds from the first frame to the last.
    pub duration: f64,
    /// Octets of the frames on the wire.
    pub bytes: u64,
    /// UDP datagrams, or first fragments of them.
    pub udp: u64,
    /// Datagrams read as RTP.
    pub rtp: u64,
    /// RTP packets in flows past the first [`FLOW_LIMIT`](crate::FLOW_LIMIT), counted in
    /// `rtp` but not measured.
    pub rtp_untracked: u64,
    /// PTP messages, over UDP or Ethernet.
    pub ptp: u64,
    /// IP fragments after the first, which carry no UDP header.
    pub fragments: u64,
    /// Frames that are none of these.
    pub other: u64,
    /// Why the file could not be read to the end, when it could not.
    pub error: Option<String>,
}

/// Which clock the capture's timestamps count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(rename_all = "lowercase"))]
pub enum Clock {
    /// PTP time.
    Ptp,
    /// UTC, TAI − UTC seconds behind PTP time: the capture's timestamps are shifted onto
    /// PTP time.
    Utc,
    /// Neither: the measurements that need PTP time are skipped.
    Unknown,
}

/// The capture's clock, and how that was decided.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TimescaleReport {
    /// The clock.
    pub clock: Clock,
    /// What decided it.
    pub basis: String,
    /// Nanoseconds added to the capture's timestamps to give PTP time.
    pub shift: i64,
    /// Anything that limits the measurements that need PTP time.
    pub note: Option<String>,
}

/// One RTP flow: the datagrams from one source address and port to one destination.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlowReport {
    /// Its number, counting from 1.
    pub index: usize,
    /// The sender's address and port.
    pub source: String,
    /// The destination address and port.
    pub destination: String,
    /// What it carries: the SDP stream's essence, or what the packets look like.
    pub essence: Essence,
    /// The SDP stream it matched, such as `camera1.sdp stream 0`.
    pub sdp: Option<String>,
    /// True when the essence was worked out from the packets, with no SDP stream.
    pub guessed: bool,
    /// The RTP payload type of its first packet.
    pub payload_type: u8,
    /// The SSRC of its first packet, in hex.
    pub ssrc: String,
    /// RTP packets.
    pub packets: u64,
    /// Octets of the IP packets.
    pub bytes: u64,
    /// When its first packet arrived: seconds since the capture began.
    pub first: f64,
    /// When its last packet arrived.
    pub last: f64,
    /// Megabits a second of IP packets, from the first packet's arrival to the last's:
    /// the octets of every packet but the first, over that time.
    pub mbps: Option<f64>,
    /// Packets that never arrived.
    pub lost: u64,
    /// Packets that arrived after a later one.
    pub out_of_order: u64,
    /// Packets that arrived more than once.
    pub duplicates: u64,
    /// Video and ancillary data measurements.
    pub video: Option<VideoReport>,
    /// Audio measurements.
    pub audio: Option<AudioReport>,
}

/// RP 2110-25 measurements of ST 2110-20, -22 and -40 streams. Times are in
/// microseconds, RTP offsets in ticks of the 90 kHz clock.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VideoReport {
    /// The frame rate, from the SDP file or the timestamps.
    pub frame_rate: Option<String>,
    /// The image height, from the SDP file or the payload headers' row numbers.
    pub height: Option<u32>,
    /// True for interlaced video.
    pub interlaced: bool,
    /// True for progressive segmented frames (PsF).
    pub segmented: bool,
    /// Frames, or fields of interlaced video: runs of packets with one timestamp.
    pub units: u64,
    /// Packets in each whole frame.
    pub packets_per_frame: Option<Stats>,
    /// NPACKETS: packets in the first whole frame, as the ST 2110-21 models count them.
    pub npackets: Option<u32>,
    /// First packet time: from the frame's reference time N × TFRAME to its first packet.
    pub fpt: Option<Stats>,
    /// RTP offset: the frame's timestamp less the one its reference time gives.
    pub rtp_offset: Option<Stats>,
    /// Latency: from the time the timestamp names to the first packet.
    pub latency: Option<Stats>,
    /// From the last packet of one frame or field to the first of the next.
    pub gap: Option<Stats>,
    /// The network compatibility model.
    pub cinst: Option<CinstReport>,
    /// The virtual receiver buffer.
    pub vrx: Option<VrxReport>,
    /// Why the ST 2110-21 models were not run, when they were not.
    pub models_skipped: Option<String>,
    /// Why the virtual receiver buffer was not modelled, when it was not.
    pub vrx_skipped: Option<String>,
    /// Each second of the timeline, as RP 2110-25 reports measurements.
    pub windows: Vec<VideoWindow>,
}

/// One second of a video stream's measurements.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VideoWindow {
    /// The second: PTP seconds when the capture's clock is known, else the capture's.
    pub second: i64,
    /// First packet time.
    pub fpt: Option<Stats>,
    /// RTP offset.
    pub rtp_offset: Option<Stats>,
    /// Latency.
    pub latency: Option<Stats>,
    /// Gaps between frames or fields.
    pub gap: Option<Stats>,
    /// The highest CINST.
    pub cinst: Option<u64>,
    /// The fullest the virtual receiver buffer was.
    pub vrx: Option<u64>,
}

/// The network compatibility model (ST 2110-21:2022 §6.6.1).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CinstReport {
    /// The highest CINST.
    pub peak: u64,
    /// The sender type that the SDP file's `TP` gives.
    pub sender_type: Option<String>,
    /// The CMAX that applies: signalled, or the sender type's.
    pub cmax: Option<u32>,
    /// The CMAX the SDP file signals.
    pub signalled_cmax: Option<u32>,
    /// CMAX for a narrow gapped sender, 2110TPN.
    pub cmax_narrow: u32,
    /// CMAX for a narrow linear sender, 2110TPNL.
    pub cmax_narrow_linear: u32,
    /// CMAX for a wide sender, 2110TPW; none from 900 000 packets a second.
    pub cmax_wide: Option<u32>,
    /// The sender types whose CMAX the peak fits.
    pub fits: Vec<String>,
    /// TDRAIN, in microseconds.
    pub drain_us: f64,
}

/// The virtual receiver buffer (ST 2110-21:2022 §6.6.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VrxReport {
    /// The read schedule: `gapped` or `linear`.
    pub schedule: String,
    /// TROFFSET: from the frame's reference time to the first read, in microseconds.
    pub troffset_us: f64,
    /// True when the SDP file signals `TROFF`, rather than TRODEFAULT applying.
    pub troffset_signalled: bool,
    /// VRXFULL: the most packets the buffer may hold.
    pub vrxfull: u64,
    /// The most it held.
    pub peak: u64,
    /// Packets that arrived after their read time.
    pub underflows: u64,
    /// Arrivals that left the buffer over VRXFULL.
    pub overflows: u64,
    /// From each packet's arrival to its read time, in microseconds.
    pub margin_us: Option<Stats>,
    /// How the buffer was modelled.
    pub method: String,
}

/// Measurements of ST 2110-30 and ST 2110-31 audio. Times are in microseconds.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AudioReport {
    /// The encoding: `L24`, `L16` or `AM824`.
    pub encoding: String,
    /// The sampling rate in Hz.
    pub sample_rate: u32,
    /// Channels, from the payload size, or else the SDP file.
    pub channels: Option<u16>,
    /// Samples in a packet, from the timestamps, or else the SDP file.
    pub samples_per_packet: Option<u32>,
    /// The packet time those samples take.
    pub packet_time_us: Option<f64>,
    /// Latency: from the time the timestamp names to the packet's arrival.
    pub latency: Option<Stats>,
    /// From one packet's arrival to the next.
    pub interval: Option<Stats>,
    /// The timestamped delay factor of each 200 ms (EBU Tech 3337).
    pub ts_df: Option<Stats>,
    /// Each second of the timeline.
    pub windows: Vec<AudioWindow>,
}

/// One second of an audio stream's measurements.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AudioWindow {
    /// The second: PTP seconds when the capture's clock is known, else the capture's.
    pub second: i64,
    /// Latency.
    pub latency: Option<Stats>,
    /// Intervals between packets.
    pub interval: Option<Stats>,
    /// The highest TS-DF of the 200 ms windows that start in it.
    pub ts_df: Option<f64>,
}

/// The PTP messages in a capture.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PtpReport {
    /// Messages decoded.
    pub messages: u64,
    /// Messages that could not be decoded.
    pub undecodable: u64,
    /// Messages from ports past the first [`PORT_LIMIT`](crate::PORT_LIMIT), counted in
    /// `messages` but not followed.
    pub untracked: u64,
    /// Each domain, in number order.
    pub domains: Vec<PtpDomainReport>,
}

/// One PTP domain.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PtpDomainReport {
    /// domainNumber.
    pub domain: u8,
    /// The grandmasters that Announce messages named, in order, up to 16.
    pub grandmasters: Vec<String>,
    /// Each port that sent messages.
    pub ports: Vec<PtpPortReport>,
    /// From the time a Sync left the grandmaster, as its timestamps and corrections give
    /// it, to its arrival in the capture, in microseconds: the capture clock's offset from
    /// PTP time plus the delay from the last clock that corrected it. Only for domains on
    /// the PTP timescale, when the capture's clock is known.
    pub sync_offset_us: Option<Stats>,
}

/// One PTP port and its messages.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PtpPortReport {
    /// sourcePortIdentity.
    pub port: String,
    /// The IP or MAC address its messages came from.
    pub address: String,
    /// Its messages, by type.
    pub messages: Vec<MessageCount>,
}

/// The messages of one type from one port.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MessageCount {
    /// The message type, such as `Sync`.
    pub kind: String,
    /// How many.
    pub count: u64,
    /// The logMessageInterval of the last one, where the type uses it.
    pub log_interval: Option<i8>,
    /// Milliseconds between messages with consecutive sequenceIds.
    pub interval_ms: Option<Stats>,
}

/// One problem found in a capture.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Finding {
    /// Identifier of the rule, from [`crate::rules`] or [`st2110_ptp::rules`].
    pub rule: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub message: String,
    /// The document and clause behind the rule.
    pub reference: &'static str,
    /// The flow, by [`FlowReport::index`], when it is about one.
    pub flow: Option<usize>,
    /// The PTP domain, when it is about one.
    pub domain: Option<u8>,
    /// When it first happened: seconds since the capture began.
    pub at: Option<f64>,
    /// How many times it happened.
    pub count: u64,
}

impl Finding {
    pub(crate) fn new(
        rule: &'static Rule,
        message: String,
        flow: Option<usize>,
        domain: Option<u8>,
        at: Option<f64>,
        count: u64,
    ) -> Self {
        Self { rule: rule.id, severity: rule.severity, message, reference: rule.reference, flow, domain, at, count }
    }
}
