//! IS-05 connection management for SMPTE ST 2110: connect Receivers to Senders the way
//! AMWA IS-05 v1.2 asks of a controller, and check that each connection took.
//!
//! - [`legs()`] reads the stream an SDP file describes as the legs a Receiver joins: one,
//!   or two for an ST 2022-7 pair.
//! - [`Constraints`] reads a Receiver's `/constraints`, and says which values it refuses.
//! - [`Plan`] is the request that connects or disconnects a Receiver, the problems its
//!   constraints would raise, and what its `/active` endpoint should show afterwards.
//!
//! The `client` feature adds [`client::ConnectionClient`], an HTTP client for
//! Connection APIs, and [`controller`], which finds Senders and Receivers in an NMOS
//! registry, connects them one at a time or as a salvo at a PTP time, puts Receivers
//! back when part of a salvo fails, and checks each connection through IS-05 and IS-04.
//!
//! ```
//! use serde_json::json;
//! use st2110_connect::{Activation, Constraints, Plan};
//!
//! let sdp = "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=CAM 1 video\r\nt=0 0\r\n\
//!     m=video 5004 RTP/AVP 96\r\nc=IN IP4 239.10.10.1/32\r\n\
//!     a=source-filter: incl IN IP4 239.10.10.1 192.168.10.21\r\na=rtpmap:96 raw/90000\r\n";
//! // An ST 2022-7 Receiver: two legs.
//! let leg = json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {}, "destination_port": {}, "rtp_enabled": {}});
//! let constraints = Constraints::from_json(&json!([leg, leg])).unwrap();
//!
//! let plan = Plan::connect(sdp, Some("5e0d0001-0000-4000-8000-000000000001"), &constraints, Activation::Immediate)
//!     .unwrap();
//! assert_eq!(plan.request["transport_params"][0]["multicast_ip"], "239.10.10.1");
//! assert_eq!(plan.request["transport_params"][0]["source_ip"], "192.168.10.21");
//! assert_eq!(plan.request["transport_params"][1], json!({"rtp_enabled": false}));
//! assert!(plan.problems.is_empty());
//! assert_eq!(
//!     plan.notes,
//!     ["the stream has one leg, so the Receiver's leg 2 is turned off: it has no ST 2022-7 protection"]
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "client")]
pub mod client;
mod constraints;
#[cfg(feature = "client")]
pub mod controller;
mod legs;
mod plan;

pub use constraints::{Constraint, Constraints};
pub use legs::{Leg, Legs, legs};
pub use plan::{Activation, Expect, Plan, tai};
