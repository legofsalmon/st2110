//! BCP-007-03 v1.0: NMOS Senders and Receivers of MXL, the shared-memory media exchange
//! between media functions on one host.
//!
//! An MXL Sender or Receiver is an IS-04 resource with the transport [`TRANSPORT`], no
//! interface bindings and, for a Sender, no transport file (`manifest_href` null, and
//! 404 from IS-05 `/transportfile`). Its IS-05 transport parameters are one set of
//! `mxl_domain_id` and `mxl_flow_id`, each an MXL UUID or null (and `auto` where it
//! may be staged), and `ext_` parameters. This program reads and checks these; it
//! carries no MXL media itself.

use serde_json::Value;

use crate::model::{Core, Model};
use crate::report::Findings;
use crate::rules::MXL_TRANSPORT;
use crate::snapshot::Snapshot;

/// The transport of an MXL Sender or Receiver.
pub const TRANSPORT: &str = "urn:x-nmos:transport:mxl";

/// The transport parameters every MXL Sender and Receiver has.
pub const PARAMETERS: [&str; 2] = ["mxl_domain_id", "mxl_flow_id"];

/// Whether `text` is an MXL UUID (`mxl_uuid.json`): lowercase, of versions 1 to 15,
/// in the RFC 4122 variant.
pub fn is_mxl_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    let hex = |b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b);
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { *b == b'-' } else { hex(b) })
        && bytes[14] != b'0'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// What is wrong with one set of MXL transport parameters, as a Sender's or a
/// Receiver's `/active` or `/staged` gives it: `staged` lets `mxl_domain_id`, and a
/// Sender's `mxl_flow_id`, be `auto`.
pub fn parameter_problems(params: &Value, sender: bool, staged: bool) -> Vec<String> {
    let Some(params) = params.as_object() else {
        return vec!["the transport parameters are not an object".into()];
    };
    let mut problems = Vec::new();
    for name in PARAMETERS {
        match params.get(name) {
            None => problems.push(format!("{name} is missing")),
            Some(Value::Null) => {}
            Some(Value::String(text)) if text == "auto" => {
                if !staged || (!sender && name == "mxl_flow_id") {
                    problems.push(format!(
                        "{name} is auto, which only a staged {} may be",
                        match (sender, name) {
                            (false, "mxl_flow_id") => "Sender's (a Receiver's never is)",
                            _ => "request",
                        }
                    ));
                }
            }
            Some(Value::String(text)) if is_mxl_uuid(text) => {}
            Some(other) => problems.push(format!("{name} is {other}, not null or a lowercase UUID")),
        }
    }
    for name in params.keys().filter(|k| !PARAMETERS.contains(&k.as_str()) && !k.starts_with("ext_")) {
        problems.push(format!("{name} is not an MXL transport parameter"));
    }
    problems
}

/// Checks the MXL Senders and Receivers in a snapshot (BCP-007-03 v1.0: Senders,
/// Receivers, IS-05 Senders and Receivers).
pub(crate) fn check(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    let active = |core: &Core<'_>, sender: bool, findings: &mut Findings| {
        let Some(active) = core.id.and_then(|id| snapshot.active.get(id)) else { return };
        let sets = active.get("transport_params").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        match sets {
            [params] => {
                for problem in parameter_problems(params, sender, false) {
                    findings.add(&MXL_TRANSPORT, core, format!("its IS-05 /active: {problem}"));
                }
            }
            _ => findings.add(
                &MXL_TRANSPORT,
                core,
                format!("its IS-05 /active has {} sets of transport parameters, not one", sets.len()),
            ),
        }
    };
    for sender in model.senders.iter().filter(|s| s.transport == Some(TRANSPORT)) {
        if let Some(href) = sender.manifest_href {
            findings.add(&MXL_TRANSPORT, &sender.core, format!("manifest_href is {href}; an MXL Sender's is null"));
        }
        if sender.interface_bindings.as_ref().is_some_and(|b| !b.is_empty()) {
            findings.add(&MXL_TRANSPORT, &sender.core, "it lists interface bindings; an MXL Sender has none");
        }
        active(&sender.core, true, findings);
    }
    for receiver in model.receivers.iter().filter(|r| r.transport == Some(TRANSPORT)) {
        if receiver.interface_bindings.as_ref().is_some_and(|b| !b.is_empty()) {
            findings.add(&MXL_TRANSPORT, &receiver.core, "it lists interface bindings; an MXL Receiver has none");
        }
        if receiver.media_types.as_ref().is_none_or(Vec::is_empty) {
            findings.add(
                &MXL_TRANSPORT,
                &receiver.core,
                "its caps.media_types is empty; an MXL Receiver lists at least one",
            );
        }
        active(&receiver.core, false, findings);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_mxl_uuids_and_transport_parameters() {
        assert!(is_mxl_uuid("3310f209-9351-47c0-b9a2-14c59b6a4c23"));
        assert!(is_mxl_uuid("3310f209-9351-f7c0-b9a2-14c59b6a4c23"), "versions up to 15");
        assert!(!is_mxl_uuid("3310F209-9351-47c0-b9a2-14c59b6a4c23"));
        assert!(!is_mxl_uuid("3310f209-9351-07c0-b9a2-14c59b6a4c23"));
        assert!(!is_mxl_uuid("3310f209-9351-47c0-c9a2-14c59b6a4c23"));
        let good = json!({"mxl_domain_id": "3310f209-9351-47c0-b9a2-14c59b6a4c23", "mxl_flow_id": null, "ext_x": 1});
        assert!(parameter_problems(&good, false, false).is_empty());
        let auto = json!({"mxl_domain_id": "auto", "mxl_flow_id": "auto"});
        assert!(parameter_problems(&auto, true, true).is_empty());
        assert_eq!(parameter_problems(&auto, false, true).len(), 1, "a Receiver's flow is never auto");
        assert_eq!(parameter_problems(&auto, true, false).len(), 2, "auto is never active");
        let bad = json!({"mxl_flow_id": 4, "destination_ip": "239.1.1.1"});
        assert_eq!(parameter_problems(&bad, true, false).len(), 3, "{:?}", parameter_problems(&bad, true, false));
    }

    /// The BCP-007-03 v1.0 examples, with a Node and Device of their own, read without
    /// a finding of this rule; broken, they are found.
    #[test]
    fn checks_the_examples_of_bcp_007_03() {
        let device = "6c370020-79bf-5cf6-8f3b-c12e3cb28b5d";
        let node = "46d7bbb2-eec2-5209-8215-90af5ccdd5a4";
        let sender = json!({
            "description": "MXL sender", "device_id": device, "flow_id": "fb75bb21-36a1-5045-8a3d-a8ee69e913d7",
            "id": "dd7b118d-9840-53ba-98e3-a44d97c55d28", "interface_bindings": [], "label": "MXL sender",
            "manifest_href": null, "subscription": {"active": true, "receiver_id": null}, "tags": {},
            "transport": TRANSPORT, "version": "1773758086:564389300",
        });
        let receiver = json!({
            "caps": {"media_types": ["video/v210"]}, "description": "MXL video receiver", "device_id": device,
            "format": "urn:x-nmos:format:video", "id": "61aa4757-7494-5e35-a99f-f6e2a7c25145",
            "interface_bindings": [], "label": "MXL video receiver", "subscription": {"active": false, "sender_id": null},
            "tags": {}, "transport": TRANSPORT, "version": "1773758086:511757900",
        });
        let flow = json!({
            "colorspace": "BT709", "description": "MXL video flow", "device_id": device,
            "format": "urn:x-nmos:format:video", "frame_height": 1080, "frame_width": 1920,
            "grain_rate": {"denominator": 1, "numerator": 60}, "id": "fb75bb21-36a1-5045-8a3d-a8ee69e913d7",
            "interlace_mode": "progressive", "label": "MXL video flow", "media_type": "video/v210", "parents": [],
            "source_id": "1100764e-6ce9-5568-8333-c8a66547f1dc", "tags": {}, "transfer_characteristic": "SDR",
            "version": "1773758086:505760400",
            "components": [{"bit_depth": 10, "height": 1080, "name": "Y", "width": 1920}],
        });
        let source = json!({
            "caps": {}, "clock_name": "clk0", "description": "MXL video source", "device_id": device,
            "format": "urn:x-nmos:format:video", "grain_rate": {"denominator": 1, "numerator": 60},
            "id": "1100764e-6ce9-5568-8333-c8a66547f1dc", "label": "MXL video source", "parents": [], "tags": {},
            "version": "1773758086:505760400",
        });
        let mut snapshot = Snapshot {
            api_version: Some("v1.3".into()),
            nodes: vec![json!({
                "id": node, "version": "1773758086:0", "label": "mxl", "description": "", "tags": {},
                "href": "http://127.0.0.1/", "hostname": "mxl", "caps": {}, "services": [], "interfaces": [],
                "api": {"versions": ["v1.3"], "endpoints": [{"host": "127.0.0.1", "port": 80, "protocol": "http", "authorization": false}]},
                "clocks": [{"name": "clk0", "ref_type": "internal"}],
            })],
            devices: vec![json!({
                "id": device, "version": "1773758086:0", "label": "mxl", "description": "", "tags": {},
                "type": "urn:x-nmos:device:generic", "node_id": node, "senders": [], "receivers": [], "controls": [],
            })],
            sources: vec![source],
            flows: vec![flow],
            senders: vec![sender.clone()],
            receivers: vec![receiver],
            ..Snapshot::default()
        };
        snapshot.active.insert(
            "dd7b118d-9840-53ba-98e3-a44d97c55d28".into(),
            json!({"receiver_id": null, "master_enable": true, "activation": {"mode": "activate_immediate",
                   "requested_time": null, "activation_time": "1755191577:297392784"},
                   "transport_params": [{"mxl_domain_id": "3310f209-9351-47c0-b9a2-14c59b6a4c23",
                                         "mxl_flow_id": "83df0a80-92d1-489d-a82b-077e2cef74cd"}]}),
        );
        let report = crate::check(&snapshot);
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.senders[0].transport.as_deref(), Some(TRANSPORT));

        snapshot.senders[0]["manifest_href"] = json!("http://127.0.0.1/sdp");
        snapshot.senders[0]["interface_bindings"] = json!(["eth0"]);
        snapshot.receivers[0]["caps"]["media_types"] = json!([]);
        snapshot.active.get_mut("dd7b118d-9840-53ba-98e3-a44d97c55d28").unwrap()["transport_params"][0]["mxl_flow_id"] =
            json!("auto");
        let report = crate::check(&snapshot);
        let found: Vec<&str> =
            report.findings.iter().filter(|f| f.rule == "mxl-transport").map(|f| f.message.as_str()).collect();
        assert_eq!(found.len(), 4, "{found:#?}");
    }
}
