//! The registry rule catalogue.
//!
//! Every finding about the registry's resources comes from one of these rules. Findings
//! in a Sender's SDP file come from [`st2110_sdp::rules`], whose identifiers never clash
//! with these.

use st2110_sdp::{Rule, Severity};

macro_rules! rules {
    ($($name:ident = $id:literal, $severity:ident, $reference:literal, $summary:literal;)+) => {
        $(
            #[doc = $summary]
            pub static $name: Rule = Rule {
                id: $id,
                severity: Severity::$severity,
                reference: $reference,
                summary: $summary,
            };
        )+

        /// Every rule, in catalogue order.
        pub static ALL: &[&Rule] = &[$(&$name),+];
    };
}

rules! {
    // Resources.
    RESOURCE_INVALID = "resource-invalid", Error, "IS-04 v1.3 schemas",
        "Each resource is a JSON object with the attributes its IS-04 schema requires, each of the right type.";
    RESOURCE_ID = "resource-id", Error, "IS-04 v1.3 APIs: Common Keys",
        "`id` is a lowercase UUID, such as `f81d4fae-7dec-11d0-a765-00a0c91e6bf6`.";
    RESOURCE_VERSION = "resource-version", Error, "IS-04 v1.3 APIs: Common Keys",
        "`version` is a TAI timestamp written `<seconds>:<nanoseconds>`.";
    DUPLICATE_ID = "duplicate-id", Error, "IS-04 v1.3 Data Model",
        "No two resources of one type share an `id`.";

    // References between resources.
    MISSING_PARENT = "missing-parent", Warning, "IS-04 v1.3 Behaviour: Registration",
        "The parent a resource names is registered: a registry accepts a resource only once it holds the parent.";
    UNKNOWN_REFERENCE = "unknown-reference", Warning, "IS-04 v1.3 schemas",
        "A Flow's Source, a Sender's Flow and the resource each subscription names are registered.";
    UNKNOWN_INTERFACE = "unknown-interface", Warning, "IS-04 v1.3 schemas",
        "Each of a Sender's or Receiver's `interface_bindings` is one of its Node's `interfaces`.";
    UNKNOWN_CLOCK = "unknown-clock", Warning, "IS-04 v1.3 schemas",
        "A Source's `clock_name` is one of its Node's `clocks`.";

    // PTP.
    PTP_UNLOCKED = "ptp-unlocked", Warning, "IS-04 v1.3 schemas",
        "Each PTP clock a Node reports is locked to a grandmaster.";
    PTP_GRANDMASTERS = "ptp-grandmasters", Warning, "IEEE 1588-2008 §9.3 · ST 2059-2:2021",
        "Every locked PTP clock follows the same grandmaster; two grandmasters mean two unaligned timing domains, unless both are traceable to TAI.";
    PTP_SDP_GRANDMASTER = "ptp-sdp-grandmaster", Warning, "ST 2110-10:2022 §8.2",
        "The grandmaster in a Sender's `a=ts-refclk` is the one its Source's clock is locked to.";

    // Connections.
    SUBSCRIPTION_STATE = "subscription-state", Error, "IS-04 v1.3 Behaviour: Nodes",
        "A subscription names a Sender or Receiver only while it is active, and a Sender names a Receiver only while it pushes a unicast stream to it.";
    INACTIVE_SENDER = "inactive-sender", Warning, "IS-04 v1.3 Behaviour: Nodes",
        "An active Receiver's Sender is active too, so the stream it expects is on the network.";
    RECEIVER_CAPS = "receiver-caps", Warning, "BCP-004-01 v1.0 · IS-04 v1.3 schemas",
        "A Receiver takes a stream its `caps` accept: its format and media type, and at least one enabled constraint set.";

    // Transport files.
    MANIFEST_HREF = "manifest-href", Error, "IS-04 v1.3 APIs: Server Side Implementation Notes",
        "An RTP Sender's `manifest_href` is an HTTP(S) URL for its SDP file.";
    MANIFEST_UNREACHABLE = "manifest-unreachable", Warning, "IS-04 v1.3 Behaviour: Nodes",
        "A Sender's SDP file can be fetched; only an inactive Sender may answer 404.";
    INTERFACE_BINDINGS = "interface-bindings", Warning, "IS-04 v1.3 Behaviour: Nodes · IS-05 v1.2 Behaviour: RTP Transport Type",
        "A Sender lists one interface binding per stream in its SDP file: two for an ST 2022-7 pair.";
    TRANSPORT_ADDRESS = "transport-address", Warning, "NMOS Parameter Registers: Transports",
        "An `rtp.mcast` Sender sends to multicast addresses and an `rtp.ucast` Sender to unicast ones.";
    FLOW_SDP = "flow-sdp", Warning, "NMOS Parameter Registers: Capabilities",
        "A Sender's SDP file describes the stream its Flow and Source advertise: media type, picture, rate, colour and audio format.";
    SENDER_SDP = "sender-sdp", Warning, "NMOS Parameter Registers: Capabilities",
        "A Sender's `st2110_21_sender_type`, `packet_transmission_mode` and `bit_rate` agree with `TP`, `packetmode` and `b=AS` in its SDP file.";
}

/// Looks a rule up by its identifier.
pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().copied().find(|rule| rule.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_kebab_case_and_apart_from_the_sdp_rules() {
        let mut seen = std::collections::HashSet::new();
        for rule in ALL {
            assert!(seen.insert(rule.id), "duplicate rule id {}", rule.id);
            assert!(st2110_sdp::rules::find(rule.id).is_none(), "{} is also an SDP rule", rule.id);
            assert!(
                rule.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "rule id {} is not kebab-case",
                rule.id
            );
            assert!(rule.summary.ends_with('.'), "summary of {} is not a sentence", rule.id);
        }
    }

    #[test]
    fn find_by_id() {
        assert_eq!(find("flow-sdp"), Some(&FLOW_SDP));
        assert_eq!(find("mediaclk-offset"), None);
    }
}
