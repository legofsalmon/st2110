//! Every registry rule, raised by a small change to a clean two-node facility, and
//! the valid variations that must not raise it.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use st2110_nmos::{Kind, Snapshot, check, rules};
use st2110_sdp::Severity;

const FACILITY: &str = include_str!("fixtures/facility.json");

const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const AUDIO_SENDER: &str = "5e0d0002-0000-4000-8000-000000000002";
const VIDEO_RECEIVER: &str = "7ecf0001-0000-4000-8000-000000000001";
const UNREGISTERED: &str = "0badbeef-0000-4000-8000-000000000000";

fn facility() -> Value {
    serde_json::from_str(FACILITY).expect("the fixture is JSON")
}

/// The facility with one change made to its JSON.
fn with(change: impl FnOnce(&mut Value)) -> Snapshot {
    let mut value = facility();
    change(&mut value);
    serde_json::from_value(value).expect("still a snapshot")
}

fn ids(snapshot: &Snapshot) -> BTreeSet<&'static str> {
    check(snapshot).findings.iter().map(|f| f.rule).collect()
}

fn audio_sdp(value: &mut Value) -> &mut Value {
    &mut value["manifests"][AUDIO_SENDER]["sdp"]
}

fn replace_in(text: &mut Value, from: &str, to: &str) {
    let old = text.as_str().expect("a string").to_string();
    assert!(old.contains(from), "no {from:?} to replace");
    *text = Value::String(old.replace(from, to));
}

/// Replaces only the first occurrence, to change one leg of a redundant pair.
fn replace_first_in(text: &mut Value, from: &str, to: &str) {
    let old = text.as_str().expect("a string").to_string();
    assert!(old.contains(from), "no {from:?} to replace");
    *text = Value::String(old.replacen(from, to, 1));
}

/// One broken facility per rule.
fn cases() -> Vec<(&'static str, Snapshot)> {
    vec![
        ("resource-invalid", with(|v| v["flows"][0]["frame_width"] = json!("1920"))),
        ("resource-id", with(|v| v["receivers"][1]["id"] = json!("7ECF0002-0000-4000-8000-000000000002"))),
        ("resource-version", with(|v| v["senders"][1]["version"] = json!("1790510437.0"))),
        (
            "duplicate-id",
            with(|v| {
                let mut copy = v["receivers"][1].clone();
                copy["label"] = json!("MON 2 audio");
                v["receivers"].as_array_mut().unwrap().push(copy);
            }),
        ),
        ("missing-parent", with(|v| v["devices"][1]["node_id"] = json!(UNREGISTERED))),
        ("unknown-reference", with(|v| v["senders"][1]["flow_id"] = json!(UNREGISTERED))),
        ("unknown-interface", with(|v| v["receivers"][0]["interface_bindings"] = json!(["eth0", "eth2"]))),
        ("unknown-clock", with(|v| v["sources"][1]["clock_name"] = json!("clk1"))),
        ("ptp-unlocked", with(|v| v["nodes"][1]["clocks"][0]["locked"] = json!(false))),
        ("ptp-grandmasters", with(|v| v["nodes"][1]["clocks"][0]["gmid"] = json!("ac-de-48-ff-fe-00-11-22"))),
        (
            "ptp-sdp-grandmaster",
            with(|v| replace_in(audio_sdp(v), "08-00-11-FF-FE-21-E1-B0", "AC-DE-48-FF-FE-00-11-22")),
        ),
        ("subscription-state", with(|v| v["senders"][0]["subscription"]["receiver_id"] = json!(VIDEO_RECEIVER))),
        ("inactive-sender", with(|v| v["senders"][0]["subscription"]["active"] = json!(false))),
        ("receiver-caps", with(|v| v["receivers"][1]["caps"]["media_types"] = json!(["audio/L16"]))),
        (
            "manifest-href",
            with(|v| {
                v["senders"][1]["manifest_href"] = Value::Null;
                v["manifests"].as_object_mut().unwrap().remove(AUDIO_SENDER);
            }),
        ),
        (
            "manifest-unreachable",
            with(|v| v["manifests"][AUDIO_SENDER] = json!({"url": "http://cam1/sdp", "status": 500})),
        ),
        ("interface-bindings", with(|v| v["senders"][0]["interface_bindings"] = json!(["eth0"]))),
        ("transport-address", with(|v| v["senders"][1]["transport"] = json!("urn:x-nmos:transport:rtp.ucast"))),
        ("flow-sdp", with(|v| v["flows"][1]["bit_depth"] = json!(16))),
        ("sender-sdp", with(|v| v["senders"][0]["st2110_21_sender_type"] = json!("2110TPW"))),
    ]
}

#[test]
fn every_rule_has_a_case() {
    let covered: BTreeSet<&str> = cases().iter().map(|(rule, _)| *rule).collect();
    for rule in rules::ALL {
        assert!(covered.contains(rule.id), "no test case raises {}", rule.id);
    }
    for rule in &covered {
        assert!(rules::find(rule).is_some(), "{rule} is not in the catalogue");
    }
}

/// Rules a case raises besides its own, because one change breaks two things.
fn also(rule: &str) -> &'static [&'static str] {
    match rule {
        // The Receiver's constraint set asks for 2110TPN.
        "sender-sdp" => &["receiver-caps"],
        _ => &[],
    }
}

#[test]
fn each_case_raises_its_rule_and_no_other() {
    for (rule, snapshot) in cases() {
        let found = ids(&snapshot);
        let expected: BTreeSet<&str> = also(rule).iter().copied().chain([rule]).collect();
        assert_eq!(found, expected, "{rule}");
    }
}

#[test]
fn findings_carry_their_rule_and_resource() {
    for (_, snapshot) in cases() {
        for finding in check(&snapshot).findings {
            let rule = rules::find(finding.rule).or_else(|| st2110_sdp::rules::find(finding.rule)).expect("catalogued");
            assert_eq!(finding.severity, rule.severity, "{}", finding.rule);
            assert_eq!(finding.reference, rule.reference, "{}", finding.rule);
            assert!(!finding.message.is_empty(), "{}", finding.rule);
            assert!(finding.resource.is_some(), "{} names no resource", finding.rule);
        }
    }
}

#[test]
fn the_facility_is_clean() {
    let snapshot = with(|_| {});
    let report = check(&snapshot);
    assert_eq!(report.findings, [], "{:#?}", report.findings);
    let summary = &report.summary;
    assert_eq!(
        (summary.nodes, summary.devices, summary.sources, summary.flows, summary.senders, summary.receivers),
        (2, 2, 2, 2, 2, 2)
    );
    assert_eq!((summary.active_senders, summary.active_receivers, summary.unlocked_clocks), (2, 2, 0));
    assert_eq!(summary.grandmasters.len(), 1);
    assert_eq!((summary.grandmasters[0].id.as_str(), summary.grandmasters[0].clocks), ("08-00-11-ff-fe-21-e1-b0", 2));

    let labels: Vec<&str> = report.senders.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["CAM 1 audio", "CAM 1 video"]);
    let video = &report.senders[1];
    assert_eq!(video.streams.len(), 2);
    assert_eq!(video.streams[1].mid.as_deref(), Some("secondary"));
    assert_eq!(video.media_type.as_deref(), Some("video/raw"));
    assert_eq!((video.node.as_deref(), video.active), (Some("Camera 1"), Some(true)));
    assert_eq!(video.receivers, [VIDEO_RECEIVER]);
    let monitor = &report.receivers[1];
    assert_eq!((monitor.label.as_str(), monitor.sender_label.as_deref()), ("MON 1 video", Some("CAM 1 video")));
}

#[test]
fn the_fixture_embeds_the_sdp_fixtures() {
    let snapshot = with(|_| {});
    let sdp = |id: &str| snapshot.manifests[id].sdp.clone().unwrap();
    assert_eq!(sdp(VIDEO_SENDER), include_str!("../../sdp/tests/fixtures/video-dup.sdp"));
    assert_eq!(sdp(AUDIO_SENDER), include_str!("../../sdp/tests/fixtures/audio-pcm.sdp"));
}

#[test]
fn sdp_findings_name_the_sender_and_line() {
    let snapshot = with(|v| replace_in(audio_sdp(v), "a=mediaclk:direct=0", "a=mediaclk:direct=5"));
    let report = check(&snapshot);
    let finding = report.findings.iter().find(|f| f.rule == "mediaclk-offset").expect("raised");
    assert_eq!(finding.severity, Severity::Error);
    assert_eq!(finding.line, Some(12));
    let sender = finding.resource.as_ref().unwrap();
    assert_eq!((sender.kind, sender.id.as_deref()), (Kind::Sender, Some(AUDIO_SENDER)));
    assert_eq!(sender.describe(), "sender \"CAM 1 audio\" (5e0d0002)");
    assert!(report.has_errors());
}

#[test]
fn messages_explain_the_mismatch() {
    let message = |snapshot: &Snapshot, rule: &str| {
        let report = check(snapshot);
        report.findings.iter().find(|f| f.rule == rule).map(|f| f.message.clone()).expect("raised")
    };
    assert_eq!(
        message(&with(|v| v["flows"][0]["frame_height"] = json!(720)), "flow-sdp"),
        "its Flow's frame_height is 720, but height is 1080"
    );
    assert_eq!(
        message(&with(|v| v["flows"][0]["interlace_mode"] = json!("interlaced_tff")), "flow-sdp"),
        "its Flow's interlace_mode is interlaced_tff, but its SDP file signals progressive video"
    );
    assert_eq!(
        message(&with(|v| v["flows"][0]["components"][1]["width"] = json!(1920)), "flow-sdp"),
        "its Flow's components are YCbCr-4:4:4, but sampling is YCbCr-4:2:2"
    );
    assert_eq!(
        message(&with(|v| v["sources"][1]["channels"].as_array_mut().unwrap().truncate(2)), "flow-sdp"),
        "its Source has 2 channels, but the SDP file carries 8"
    );
    assert_eq!(
        message(&with(|v| v["flows"][0]["grain_rate"] = json!({"numerator": 25})), "flow-sdp"),
        "its Flow's grain_rate is 25, but exactframerate is 50"
    );
    assert_eq!(
        message(
            &with(|v| v["receivers"][0]["caps"]["constraint_sets"][0]["urn:x-nmos:cap:format:frame_width"] =
                json!({"enum": [3840]})),
            "receiver-caps"
        ),
        "none of its constraint sets accepts what sender \"CAM 1 video\" (5e0d0001) sends: \
         \"1080p\": frame_width 1920 is not one of 3840; \"720p\": frame_height 1080 is not one of 720"
    );
    assert_eq!(
        message(&with(|v| v["nodes"][1]["clocks"][0]["gmid"] = json!("ac-de-48-ff-fe-00-11-22")), "ptp-grandmasters"),
        "PTP clock clk0 follows grandmaster ac-de-48-ff-fe-00-11-22, but most locked clocks (1 of 2) follow \
         08-00-11-ff-fe-21-e1-b0"
    );
    assert_eq!(
        message(&with(|v| v["senders"][0]["interface_bindings"] = json!(["eth0"])), "interface-bindings"),
        "it lists 1 interface binding for the 2 streams in its SDP file"
    );
    assert_eq!(
        message(
            &with(|v| {
                v["senders"][1]["bit_rate"] = json!(2500);
                replace_in(audio_sdp(v), "/32\n", "/32\nb=AS:2300\n");
            }),
            "sender-sdp"
        ),
        "its bit_rate is 2500 kbit/s, but b=AS is 2300"
    );
}

#[test]
fn valid_variations_are_clean() {
    let clean = |name: &str, snapshot: Snapshot| {
        let findings = check(&snapshot).findings;
        assert!(findings.is_empty(), "{name}: {findings:#?}");
    };
    // An inactive Sender may answer 404 for its SDP file, and a Receiver that is not
    // taking a stream names no Sender.
    clean(
        "inactive sender",
        with(|v| {
            v["senders"][1]["subscription"]["active"] = json!(false);
            v["receivers"][1]["subscription"] = json!({"sender_id": null, "active": false});
            v["manifests"][AUDIO_SENDER] = json!({"url": "http://cam1/sdp", "status": 404});
        }),
    );
    // The same NIC listed twice for both legs of an ST 2022-7 pair.
    clean("one NIC for both legs", with(|v| v["senders"][0]["interface_bindings"] = json!(["eth0", "eth0"])));
    // A constraint set that is disabled is ignored, and one with nothing to evaluate
    // is satisfied.
    clean(
        "disabled and unknown constraints",
        with(|v| {
            let sets = v["receivers"][0]["caps"]["constraint_sets"].as_array_mut().unwrap();
            sets.insert(
                0,
                json!({"urn:x-nmos:cap:meta:enabled": false, "urn:x-nmos:cap:format:frame_width": {"enum": [3840]}}),
            );
            sets.push(json!({"urn:x-vendor:cap:magic": {"enum": [1]}}));
            sets.remove(1);
        }),
    );
    // Before IS-04 v1.1 a Flow had no Device, a Source no clock and a Node no clocks.
    clean(
        "v1.0 resources",
        with(|v| {
            for key in ["device_id", "media_type", "bit_depth"] {
                v["flows"][1].as_object_mut().unwrap().remove(key);
            }
            v["sources"][1].as_object_mut().unwrap().remove("clock_name");
            v["nodes"][1].as_object_mut().unwrap().remove("clocks");
        }),
    );
    // A snapshot read without SDP files.
    clean("no SDP files", with(|v| v["manifests"] = json!({})));
    // b=AS within rounding of bit_rate.
    clean(
        "bit rate rounding",
        with(|v| {
            v["senders"][1]["bit_rate"] = json!(2301);
            replace_in(audio_sdp(v), "/32\n", "/32\nb=AS:2300\n");
        }),
    );
}

#[test]
fn findings_are_grouped_by_resource() {
    let snapshot = with(|v| {
        v["receivers"][0]["interface_bindings"] = json!(["eth0", "eth2"]);
        v["nodes"][1]["clocks"][0]["locked"] = json!(false);
        replace_first_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], "TP=2110TPN", "TP=2110TPNL");
    });
    let order: Vec<(Kind, &str)> =
        check(&snapshot).findings.iter().map(|f| (f.resource.as_ref().unwrap().kind, f.rule)).collect();
    assert_eq!(
        order,
        [
            (Kind::Node, "ptp-unlocked"),
            (Kind::Sender, "sender-sdp"),
            (Kind::Sender, "dup-mismatch"),
            (Kind::Receiver, "unknown-interface")
        ],
        "the node first, then the sender's own finding before its SDP file's, then the receiver"
    );
}

#[test]
fn snapshots_round_trip_as_json() {
    let snapshot = with(|_| {});
    assert_eq!(Snapshot::from_json(&snapshot.to_json()).unwrap(), snapshot);
    // Everything is optional, so an empty object is an empty registry.
    let empty = Snapshot::from_json("{}").unwrap();
    assert_eq!(check(&empty).summary.nodes, 0);
}

#[test]
fn docs_list_every_rule() {
    let docs = include_str!("../../../docs/rules.md");
    assert!(
        docs.contains(&st2110_sdp::rules::markdown_table(rules::ALL)),
        "docs/rules.md is stale: run `st2110 rules --format markdown > docs/rules.md`"
    );
}
