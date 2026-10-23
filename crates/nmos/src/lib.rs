//! Read-only checks of an AMWA NMOS registry and the SDP files its Senders publish.
//!
//! A [`Snapshot`] holds every resource a registry's IS-04 Query API returned, and the
//! SDP file each Sender's `manifest_href` points to. [`check`] reads it the way a
//! controller would and reports what would trip one up, citing the document behind
//! each rule in [`rules`]:
//!
//! - resources that break their IS-04 schema, and references to resources that are
//!   not registered;
//! - PTP clocks that are unlocked or follow different grandmasters;
//! - subscriptions that contradict themselves, Receivers taking a stream from an
//!   inactive Sender or one their BCP-004-01 capabilities reject;
//! - SDP files that cannot be fetched, that break ST 2110 (checked with
//!   [`st2110_sdp::lint`]), or that disagree with the Flow, Source and Sender they
//!   describe.
//!
//! [`routing`] reads what a controller needs to make connections: the Sender or
//! Receiver a name refers to, its Device's IS-05 Connection API, and the crosspoint
//! matrix of which Senders each Receiver can take. [`groups`] reads the BCP-002-01
//! natural groups, such as a camera's video and audio, so a controller can take one as
//! a whole. [`ncp`] holds the IS-12 control model, and the BCP-008 status monitors that
//! say how each Receiver and Sender is doing.
//!
//! The `client` feature adds [`client::QueryClient`], which reads a snapshot from a
//! live registry, IS-10 tokens for it to send ([`auth`]), and the checks a Node makes of
//! the tokens sent to it ([`access`]).
//!
//! ```
//! use st2110_nmos::{Snapshot, check};
//! use serde_json::json;
//!
//! let snapshot = Snapshot {
//!     nodes: vec![json!({
//!         "id": "3b8be755-08ff-452b-b217-c9151eb21193", "version": "1441716120:0", "label": "Camera 1",
//!         "href": "http://192.168.10.21/", "clocks": [
//!             {"name": "clk0", "ref_type": "ptp", "traceable": false, "version": "IEEE1588-2008",
//!              "gmid": "08-00-11-ff-fe-21-e1-b0", "locked": false}
//!         ],
//!     })],
//!     ..Snapshot::default()
//! };
//! let report = check(&snapshot);
//! assert_eq!(report.summary.unlocked_clocks, 1);
//! assert_eq!(report.findings[0].rule, "ptp-unlocked");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "client")]
pub mod access;
#[cfg(feature = "client")]
pub mod auth;
mod caps;
mod check;
#[cfg(feature = "client")]
pub mod client;
mod controls;
pub mod groups;
mod model;
pub mod monitors;
pub mod ncp;
mod report;
pub mod routing;
pub mod rules;
mod snapshot;
#[cfg(feature = "client")]
pub mod tls;
#[cfg(feature = "client")]
pub mod ws;

pub use check::check;
pub use model::Kind;
pub use report::{
    ChannelMapView, ChannelRoute, Finding, Grandmaster, InterfaceView, MonitorView, NodeView, OutputMap, ReceiverView,
    Report, ResourceRef, SenderView, Summary, SystemView,
};
pub use snapshot::{Manifest, Snapshot, System};
