//! RP 2110-25 measurements of SMPTE ST 2110 streams in packet captures, with a monitor
//! of the PTP messages alongside them.
//!
//! [`analyse`] reads a pcap or pcapng file and, for each RTP flow in it:
//!
//! - matches it to a stream in the SDP files given, or works out from its packets what
//!   it carries;
//! - counts lost, reordered and duplicated packets, and checks the ST 2110-10 limits on
//!   datagram size and fragmentation;
//! - for video and ancillary data, measures what RP 2110-25 asks for (first packet time,
//!   RTP offset, latency and the gaps between frames) and runs the two ST 2110-21 timing
//!   models, the network compatibility model (CINST) and the virtual receiver buffer (VRX);
//! - for audio, measures latency, packet intervals and the timestamped delay factor of
//!   EBU Tech 3337, and checks the packet time and channel count against the SDP file.
//!
//! PTP messages are decoded and checked against the ST 2059-2 profile, and followed
//! across the capture: grandmaster changes, rival masters, message rates, and Sync and
//! Delay_Req messages left without their Follow_Up or Delay_Resp.
//!
//! The measurements that compare arrival times with RTP timestamps need the capture's
//! clock on PTP time. A capture made on UTC is 37 seconds (TAI − UTC) behind, which the
//! analyser tells from the PTP messages or the RTP timestamps and shifts back.
//!
//! ```
//! use st2110_pcap::{Options, analyse};
//!
//! // A pcap file header with no packets.
//! let empty = [
//!     0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
//! ];
//! let report = analyse(&empty[..], &Options::default()).unwrap();
//! assert_eq!((report.capture.format.as_str(), report.capture.frames), ("pcap", 0));
//! assert!(report.flows.is_empty() && report.findings.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyser;
mod audio;
pub mod capture;
mod flow;
pub mod net;
mod ptp;
mod report;
pub mod rtp;
pub mod rules;
mod stats;
mod timescale;
mod video;

pub use analyser::{Analyser, analyse};
pub use capture::{CaptureError, Format, Frame, Reader};
pub use report::{
    AudioReport, AudioWindow, Capture, CinstReport, Clock, Finding, FlowReport, MessageCount, PtpDomainReport,
    PtpPortReport, PtpReport, Report, TimescaleReport, VideoReport, VideoWindow, VrxReport,
};
pub use stats::Stats;

/// Flows measured in a capture, at most: packets of any more are counted in
/// [`Capture::rtp_untracked`].
pub const FLOW_LIMIT: usize = 10_000;

/// PTP ports followed in a capture, at most: messages from any more are counted in
/// [`PtpReport::untracked`].
pub const PORT_LIMIT: usize = 10_000;

/// An SDP file whose streams flows are matched against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdpFile {
    /// A name for it in the report, such as its file name.
    pub name: String,
    /// Its text.
    pub text: String,
}

/// Which clock the capture's timestamps count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Timescale {
    /// Work it out from the PTP messages, or else the RTP timestamps.
    #[default]
    Auto,
    /// PTP time.
    Ptp,
    /// UTC.
    Utc,
}

/// How to analyse a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// SDP files to match flows against.
    pub sdp: Vec<SdpFile>,
    /// Which clock the capture's timestamps count.
    pub timescale: Timescale,
    /// TAI − UTC in seconds: how far a capture on UTC is behind PTP time.
    pub tai_utc: i32,
}

impl Default for Options {
    fn default() -> Self {
        Self { sdp: Vec::new(), timescale: Timescale::Auto, tai_utc: st2110_ptp::TAI_UTC_2017 }
    }
}

/// `1 packet`, `2 packets`.
pub(crate) fn plural(count: u64, word: &str) -> String {
    if count == 1 { format!("1 {word}") } else { format!("{count} {word}s") }
}

/// Places analysis times, which are PTP time when the capture's clock is known, on the
/// capture's own timeline, in seconds since its first frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timeline {
    /// The first frame's capture time, in nanoseconds.
    pub start: i128,
    /// Nanoseconds added to capture times to give analysis times.
    pub shift: i128,
}

impl Timeline {
    pub(crate) fn at(&self, t: Option<i128>) -> Option<f64> {
        t.map(|t| (t - self.shift - self.start) as f64 / 1e9)
    }
}

/// A span of time in nanoseconds, in the unit that suits it.
pub(crate) fn duration(nanos: i128) -> String {
    let magnitude = nanos.unsigned_abs();
    if magnitude < 1_000 {
        format!("{nanos} ns")
    } else if magnitude < 1_000_000 {
        format!("{:.1} µs", nanos as f64 / 1e3)
    } else if magnitude < 1_000_000_000 {
        format!("{:.3} ms", nanos as f64 / 1e6)
    } else {
        format!("{:.6} s", nanos as f64 / 1e9)
    }
}
