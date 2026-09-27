//! PTP for SMPTE ST 2110: decode IEEE 1588 messages, check them against the ST 2059-2
//! profile, and do the ST 2059-1 arithmetic that ties media signals to PTP time.
//!
//! - [`decode`] reads a PTP message, such as the payload of a UDP datagram to port 319
//!   or 320, including the synchronization metadata TLV an ST 2059-2 grandmaster sends.
//! - [`check`] lists what in a message breaks the profile, each finding tied to a rule
//!   in the [`rules`] catalogue and the clause behind it.
//! - [`epoch`] finds alignment points, frame counts and RTP timestamps from PTP time,
//!   and [`timecode`] the time code a daily jam gives; [`timing`] puts them together
//!   for a set of signals.
//!
//! ```
//! use st2110_ptp::epoch::{self, Signal};
//! use st2110_ptp::PtpTime;
//! use st2110_sdp::Rational;
//!
//! // 2026-09-27 12:00:00.123456789 UTC.
//! let now = PtpTime::parse("1790510437.123456789").unwrap();
//! let rate = Rational::new(60000, 1001).unwrap();
//! let (frame, at) = epoch::next_alignment(now, Signal::Video(rate)).unwrap();
//! assert_eq!(at.to_string(), "1790510437.132083334");
//! assert_eq!(epoch::frame_rtp_timestamp(frame, rate, 90_000), Some(3_061_363_263));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod check;
pub mod describe;
pub mod epoch;
mod message;
pub mod rules;
mod smpte;
mod time;
pub mod timecode;
pub mod timing;

pub use check::{Finding, check};
pub use message::{
    Action, Announce, Body, ClockQuality, DecodeError, Flags, HEADER_LENGTH, Header, Management, Message, MessageType,
    PortIdentity, Timestamp, Tlv, TlvContent, TlvError, decode, tlv_type,
};
pub use smpte::{LockingStatus, SMPTE_OUI, SYNC_METADATA_SUBTYPE, SyncMetadata};
pub use time::{Civil, PtpTime, TAI_UTC_2017};
