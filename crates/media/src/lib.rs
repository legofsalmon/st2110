//! Send and receive SMPTE ST 2110-20 video and ST 2110-30 audio on ordinary UDP
//! sockets, with ST 2022-7 seamless protection.
//!
//! - [`format`] describes the picture or sound, and [`describe`] the stream: its SDP
//!   file, written for a sender and read for a receiver.
//! - [`video`] and [`audio`] cut frames and samples into RTP packets and put them back
//!   together; [`pixels`] packs 8-bit R'G'B' pictures into ST 2110-20 pixel groups.
//! - [`send`] sends colour bars or a tone, each packet at its ST 2110-21 time, lined up
//!   with the SMPTE Epoch; [`pattern`] draws them.
//! - [`merge`] merges the legs of an ST 2022-7 pair and measures how far apart they are;
//!   [`receive`] follows a stream through it and reports what it finds.
//! - [`files`] writes PNG pictures, WAV files and pcap captures.
//! - With the `net` feature, [`net`] sends and receives on UDP sockets. Without it the
//!   crate does no I/O of its own, so senders can write captures and receivers can
//!   read them.
//!
//! ```
//! use st2110_media::describe::{Clock, Description, Leg, Media};
//! use st2110_media::format::VideoFormat;
//! use st2110_media::receive::Session;
//! use st2110_media::send::{Output, Sender};
//!
//! // Two frames of 720p50 bars, received as they were sent.
//! struct Loopback<'a>(&'a mut Session);
//!
//! impl Output for Loopback<'_> {
//!     fn send(&mut self, packet: &[u8], at: i128) -> std::io::Result<()> {
//!         self.0.push(0, "192.168.1.10".parse().unwrap(), at + 50_000, packet, &mut ());
//!         Ok(())
//!     }
//! }
//!
//! let stream = Description {
//!     name: "Bars".into(),
//!     media: Media::Video(VideoFormat::from_name("720p50").unwrap()),
//!     payload_type: 96,
//!     legs: vec![Leg { destination: "239.1.1.1:5004".parse().unwrap(), source: Some("192.168.1.10".parse().unwrap()) }],
//!     clock: Some(Clock::Traceable),
//!     ttl: 32,
//! };
//! assert!(stream.sdp(1).contains("a=fmtp:96 sampling=YCbCr-4:2:2; width=1280; height=720; exactframerate=50;"));
//!
//! let mut session = Session::new(&stream).unwrap();
//! let mut sender = Sender::new(&stream, 1000, -18.0, 0x1234, 0).unwrap();
//! // 2026-09-27 12:00:00 UTC, in nanoseconds of TAI, for 40 ms.
//! let start = 1_790_510_437 * 1_000_000_000;
//! let sent = sender.run(&mut Loopback(&mut session), start, start + 40_000_000).unwrap();
//! session.finish(&mut ());
//!
//! let report = session.report();
//! assert_eq!((sent.frames, report.video.unwrap().counts.whole), (2, 2));
//! assert!(report.problems.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audio;
pub mod describe;
pub mod files;
pub mod format;
pub mod merge;
#[cfg(feature = "net")]
pub mod net;
pub mod pattern;
pub mod pixels;
pub mod receive;
mod rtp;
pub mod send;
pub mod video;
