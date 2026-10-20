//! What was read from a registry, kept as the registry returned it.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every resource a registry's Query API returned, and the SDP file each Sender's
/// `manifest_href` pointed to.
///
/// Resources stay as raw JSON so that a saved snapshot records exactly what the
/// registry said, including anything malformed; [`check`](crate::check) reads them
/// tolerantly. A snapshot saved with `st2110 nmos --save` can be checked again later
/// without the registry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Where the resources came from, such as the Query API URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The Query API version they were read through, such as `v1.3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    /// The `id` of each resource known to be at `api_version`, so held to that
    /// version's schema; `None` when that is not known, as when a registry returned
    /// resources of several versions without saying which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<BTreeSet<String>>,
    /// Node resources.
    pub nodes: Vec<Value>,
    /// Device resources.
    pub devices: Vec<Value>,
    /// Source resources.
    pub sources: Vec<Value>,
    /// Flow resources.
    pub flows: Vec<Value>,
    /// Sender resources.
    pub senders: Vec<Value>,
    /// Receiver resources.
    pub receivers: Vec<Value>,
    /// What each Sender's `manifest_href` returned, keyed by Sender `id`.
    pub manifests: BTreeMap<String, Manifest>,
    /// What each Sender's IS-05 `/transportfile` returned, keyed by Sender `id`, where
    /// its Device's Connection API serves it at a URL other than `manifest_href`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub transport_files: BTreeMap<String, Manifest>,
    /// What each Sender's and Receiver's IS-05 `/active` returned, keyed by `id`,
    /// where its Device advertises a Connection API and the read succeeded.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub active: BTreeMap<String, Value>,
    /// What each Sender's and Receiver's IS-11 Stream Compatibility Management API
    /// returned, keyed by `id`, where its Device advertises one: an object with the
    /// `status` of each and, for a Sender, its `/constraints/active` as `active` and
    /// its `/constraints/supported` as `supported`, each left out when it could not be
    /// read.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub stream_compat: BTreeMap<String, Value>,
    /// What each Device's IS-08 Channel Mapping API returned, keyed by Device `id`,
    /// where it advertises one: an object with its `io` and its `map/active` as
    /// `active`, each left out when it could not be read.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub channel_mapping: BTreeMap<String, Value>,
    /// What the IS-09 System API returned, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<System>,
}

/// The result of reading the IS-09 System API's global configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct System {
    /// The URL of its `/global` resource.
    pub url: String,
    /// What `/global` returned, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<Value>,
    /// Why it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The result of fetching one Sender's transport file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Manifest {
    /// The URL that was fetched.
    pub url: String,
    /// The HTTP status, when a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The body of a successful response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    /// Why the fetch failed, when no response arrived or it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Manifest {
    /// A transport file that was fetched.
    pub fn fetched(url: impl Into<String>, sdp: impl Into<String>) -> Self {
        Self { url: url.into(), status: Some(200), sdp: Some(sdp.into()), error: None }
    }
}

impl Snapshot {
    /// Reads a snapshot saved as JSON.
    pub fn from_json(text: &str) -> serde_json::Result<Self> {
        serde_json::from_str(text)
    }

    /// The snapshot as pretty-printed JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a snapshot always serializes")
    }
}
