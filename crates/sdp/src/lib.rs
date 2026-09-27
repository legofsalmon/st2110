//! Parse SMPTE ST 2110 session descriptions and check them against the standards.
//!
//! [`lint`] reads an SDP file, describes each stream it declares and reports every
//! problem it finds, each tied to a rule in the [`rules`] catalogue and to the clause
//! of the standard behind it.
//!
//! ```
//! use st2110_sdp::Severity;
//!
//! let sdp = "v=0\r\n\
//! o=- 1 1 IN IP4 192.168.1.10\r\n\
//! s=Camera 1 audio\r\n\
//! t=0 0\r\n\
//! m=audio 5004 RTP/AVP 97\r\n\
//! c=IN IP4 239.1.1.2/32\r\n\
//! a=source-filter: incl IN IP4 239.1.1.2 192.168.1.10\r\n\
//! a=rtpmap:97 L24/48000/2\r\n\
//! a=fmtp:97 channel-order=SMPTE2110.(ST)\r\n\
//! a=ptime:1\r\n\
//! a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127\r\n\
//! a=mediaclk:direct=5\r\n";
//!
//! let report = st2110_sdp::lint(sdp);
//! assert_eq!(report.streams[0].summary, "L24 48 kHz, 2 channels (ST), 1 ms, level A, 2.30 Mb/s");
//! assert_eq!(report.count(Severity::Error), 1);
//! let error = report.diagnostics.iter().find(|d| d.severity == Severity::Error).unwrap();
//! assert_eq!((error.rule, error.line), ("mediaclk-offset", Some(12)));
//! assert_eq!(error.reference, "ST 2110-10:2022 §7.3");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audio;
mod clock;
mod diag;
mod fmtp;
mod lint;
mod rational;
pub mod rules;
mod sdp;
mod stream;
pub mod video;

pub use clock::{ClockIdentity, MediaClock, RefClock};
pub use diag::{Diagnostic, Rule, Severity};
pub use fmtp::{Fmtp, Param};
pub use rational::{FrameRateError, Notation, Rational, parse_frame_rate};
pub use sdp::{
    Attribute, Connection, Field, MediaLine, Origin, RtpMap, Section, SessionDescription, SourceFilter, parse,
    parse_bandwidth, parse_connection, parse_media_line, parse_origin, parse_rtpmap, parse_source_filter,
};
pub use stream::{Essence, Stream};

/// What [`lint`] found in one session description.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Report {
    /// One entry per media section, in order.
    pub streams: Vec<Stream>,
    /// Every finding, in line order.
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    /// True if any finding is an error.
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| d.severity == Severity::Error)
    }

    /// The number of findings of one severity.
    pub fn count(&self, severity: Severity) -> usize {
        self.diagnostics.iter().filter(|d| d.severity == severity).count()
    }
}

/// Parses a session description, describes its streams and checks it against
/// ST 2110 and the documents it builds on.
pub fn lint(text: &str) -> Report {
    let mut diagnostics = diag::Diagnostics::default();
    let sdp = sdp::parse_into(text, &mut diagnostics);
    let media = stream::build(&sdp, &mut diagnostics);
    lint::run(&sdp, &media, &mut diagnostics);
    Report { streams: media.iter().map(stream::summarize).collect(), diagnostics: diagnostics.into_sorted() }
}
