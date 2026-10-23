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
    INTERFACE_LLDP = "interface-lldp", Info, "IS-04 v1.3 schemas: Node",
        "Each of a Node's `interfaces` gives the LLDP `chassis_id` it sends, as a lowercase MAC address with dashes where it is one, and at IS-04 v1.3 the switch port it is plugged into (`attached_network_device`), so a controller can tell where each stream enters the network.";
    UNKNOWN_CLOCK = "unknown-clock", Warning, "IS-04 v1.3 schemas",
        "A Source's `clock_name` is one of its Node's `clocks`.";

    // Tags.
    GROUP_HINT = "group-hint", Warning, "BCP-002-01 v1.0 · NMOS Parameter Registers: Tags (grouphint)",
        "Each `urn:x-nmos:tag:grouphint/v1.0` value is `<group>:<role>`, with `:device` or `:node` after it for its scope, and no two Senders, or two Receivers, have one role in one group, so a controller can take a natural group, such as a camera's video and audio, as one.";
    ASSET_TAGS = "asset-tags", Warning, "BCP-002-02 v1.0",
        "A Node or Device that gives any `urn:x-nmos:tag:asset:` tag gives exactly one Manufacturer, Product Name and Instance Identifier, a Device at least one Function, and no two Nodes, or two Devices, give the same three, so crew can tell one box of a model from another.";

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
    ACTIVE_SUBSCRIPTION = "active-subscription", Warning, "IS-05 v1.1 Interoperability: IS-04 · IS-04 v1.3 Behaviour: Nodes",
        "A Sender's or Receiver's `subscription` in the registry says what its IS-05 `/active` does: `active` is `master_enable`, and the Receiver or Sender it names is the `receiver_id` or `sender_id` there while enabled, otherwise none.";
    INACTIVE_SENDER = "inactive-sender", Warning, "IS-04 v1.3 Behaviour: Nodes",
        "An active Receiver's Sender is active too, so the stream it expects is on the network.";
    CONSTRAINT_SETS = "constraint-sets", Warning, "BCP-004-01 v1.0: Receiver Capabilities",
        "A Receiver with `caps.constraint_sets` also gives `caps.version`, and each constraint set holds at least one parameter constraint besides the `urn:x-nmos:cap:meta:` attributes.";
    RECEIVER_CAPS = "receiver-caps", Warning, "BCP-004-01 v1.0 · IS-04 v1.3 schemas · IS-07 v1.0.1 Event types",
        "A Receiver takes a stream its `caps` accept: its format, media type and IS-07 event type, and at least one enabled constraint set.";
    SENDER_CAPS = "sender-caps", Warning, "BCP-004-02 v1.0: Sender Capabilities",
        "A Sender with `caps.constraint_sets` also gives `caps.version`, each constraint set holds at least one parameter constraint, and the stream it sends satisfies at least one enabled set.";

    // Stream compatibility (IS-11).
    STREAM_COMPAT = "stream-compat", Warning, "IS-11 v1.0 Behaviour: Client Side",
        "No Sender's IS-11 `status` is `active_constraints_violation` or `no_essence`, and no active Receiver's is `non_compliant_stream`: a controller reports each of these to its user.";
    ACTIVE_CONSTRAINTS = "active-constraints", Warning, "IS-11 v1.0 Behaviour: Server Side · BCP-004-02 v1.0",
        "A Sender's IS-11 active constraints use only the parameter constraints its `/constraints/supported` lists, and while it sends, its stream satisfies at least one of them; a Sender that violates them stops sending.";

    // Channel mapping (IS-08).
    CHANNEL_MAP = "channel-map", Warning, "IS-08 v1.0.1 Behaviour",
        "A Device's IS-08 active map names only its Outputs and their channels, routes only Input channels that exist, and routes an Input to an Output only where the Output's `routable_inputs` allow it.";

    // Status monitoring (IS-12, BCP-008).
    NCP_CONTROL = "ncp-control", Warning, "IS-12 v1.0.1: Transport, IS-04 interactions · MS-05-02 v1.0: Blocks, Managers",
        "A Device's `urn:x-nmos:control:ncp/v1.0` control is a ws:// or wss:// URL whose endpoint answers IS-12 commands, with a root block of role `root` that holds a DeviceManager and a ClassManager.";
    MONITOR_TOUCHPOINT = "monitor-touchpoint", Warning, "BCP-008-01 v1.0 · BCP-008-02 v1.0: Touchpoints",
        "Each Receiver or Sender monitor names exactly one Receiver or Sender, of the kind it watches, in its `x-nmos` touchpoints, that is registered as one of its own Device's, and no two monitors watch the same one.";
    MONITOR_STATUS = "monitor-status", Warning, "BCP-008-01 v1.0 · BCP-008-02 v1.0: Controller",
        "No monitor's overall status is `Unhealthy` or `PartiallyHealthy`: a controller shows the status, and the Device's message as it words it, to its user.";
    MONITOR_ACTIVITY = "monitor-activity", Warning, "BCP-008-01 v1.0 · BCP-008-02 v1.0: Overall status, Deactivating",
        "A monitor's overall status is `Inactive` exactly while the Receiver or Sender it watches is inactive in the registry, and its connection or transmission and stream or essence statuses are `Inactive` with it.";

    // System parameters (IS-09).
    SYSTEM_GLOBAL = "system-global", Warning, "IS-09 v1.0 System API: global.json · JT-NM TR-1001-1:2020",
        "The System API's `/global` can be read, and gives `is04.heartbeat_interval` (1 to 1000 s), the PTP `domain_number` (0 to 127) and `announce_receipt_timeout` (2 to 10) that every Node in the system uses.";
    SYSTEM_PTP_DOMAIN = "system-ptp-domain", Warning, "IS-09 v1.0 · ST 2110-10:2022 §8.2",
        "The PTP domain in each Sender's `a=ts-refclk` is the `domain_number` the System API gives the system.";

    // Transport files.
    MANIFEST_HREF = "manifest-href", Error, "IS-04 v1.3 APIs: Server Side Implementation Notes",
        "An RTP Sender's `manifest_href` is an HTTP(S) URL for its SDP file.";
    MANIFEST_UNREACHABLE = "manifest-unreachable", Warning, "IS-04 v1.3 Behaviour: Nodes",
        "A Sender's SDP file can be fetched; only an inactive Sender may answer 404.";
    MANIFEST_TRANSPORTFILE = "manifest-transportfile", Warning, "IS-04 v1.3 Behaviour: Nodes · IS-05 v1.2 Overview",
        "A Sender's `manifest_href` serves the stream its IS-05 `/transportfile` does, so a controller that reads either connects Receivers to what the Sender sends.";
    INTERFACE_BINDINGS = "interface-bindings", Warning, "IS-04 v1.3 Behaviour: Nodes · IS-05 v1.2 Behaviour: RTP Transport Type",
        "A Sender lists one interface binding per stream in its SDP file: two for an ST 2022-7 pair.";
    TRANSPORT_ADDRESS = "transport-address", Warning, "NMOS Parameter Registers: Transports",
        "An `rtp.mcast` Sender sends to multicast addresses and an `rtp.ucast` Sender to unicast ones.";
    FLOW_SDP = "flow-sdp", Warning, "NMOS Parameter Registers: Capabilities",
        "A Sender's SDP file describes the stream its Flow and Source advertise: media type, picture, rate, colour and audio format.";
    SENDER_SDP = "sender-sdp", Warning, "NMOS Parameter Registers: Capabilities",
        "A Sender's `st2110_21_sender_type`, `packet_transmission_mode` and `bit_rate` agree with `TP`, `packetmode` and `b=AS` in its SDP file.";

    // MXL (BCP-007-03).
    MXL_TRANSPORT = "mxl-transport", Warning, "BCP-007-03 v1.0",
        "An MXL (`urn:x-nmos:transport:mxl`) Sender has `manifest_href` null and no `interface_bindings`, an MXL Receiver no `interface_bindings` and at least one of `caps.media_types`, and the IS-05 `/active` of each holds one set of transport parameters, `mxl_domain_id` and `mxl_flow_id`, each null or a lowercase UUID.";
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
