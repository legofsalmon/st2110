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

/// Gives the audio Sender's Connection API a `/transportfile` of its own: its SDP
/// file, changed.
fn transport_file(value: &mut Value, change: impl FnOnce(&mut Value)) {
    let mut file = value["manifests"][AUDIO_SENDER].clone();
    file["url"] =
        json!(format!("http://192.168.10.21/x-nmos/connection/v1.1/single/senders/{AUDIO_SENDER}/transportfile"));
    change(&mut file["sdp"]);
    value["transport_files"] = json!({AUDIO_SENDER: file});
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
        ("interface-lldp", with(|v| v["nodes"][0]["interfaces"][1]["chassis_id"] = Value::Null)),
        ("unknown-clock", with(|v| v["sources"][1]["clock_name"] = json!("clk1"))),
        ("ptp-unlocked", with(|v| v["nodes"][1]["clocks"][0]["locked"] = json!(false))),
        ("ptp-grandmasters", with(|v| v["nodes"][1]["clocks"][0]["gmid"] = json!("ac-de-48-ff-fe-00-11-22"))),
        (
            "ptp-sdp-grandmaster",
            with(|v| replace_in(audio_sdp(v), "08-00-11-FF-FE-21-E1-B0", "AC-DE-48-FF-FE-00-11-22")),
        ),
        ("subscription-state", with(|v| v["senders"][0]["subscription"]["receiver_id"] = json!(VIDEO_RECEIVER))),
        (
            "active-subscription",
            with(|v| v["active"] = json!({VIDEO_RECEIVER: {"master_enable": true, "sender_id": AUDIO_SENDER}})),
        ),
        ("inactive-sender", with(|v| v["senders"][0]["subscription"]["active"] = json!(false))),
        (
            "constraint-sets",
            with(|v| {
                v["receivers"][1]["caps"].as_object_mut().unwrap().remove("version");
            }),
        ),
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
        ("manifest-transportfile", with(|v| transport_file(v, |sdp| replace_in(sdp, "239.10.10.2", "239.10.10.9")))),
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
    assert_eq!(
        message(
            &with(|v| {
                v["senders"][0]["interface_bindings"] = json!(["eth0"]);
                one_media_section(v);
            }),
            "interface-bindings"
        ),
        "it lists 1 interface binding for the 2 streams in its SDP file"
    );
    assert_eq!(
        message(
            &with(|v| {
                v["senders"][1]["transport"] = json!("urn:x-nmos:transport:websocket");
                v["senders"][1]["subscription"]["receiver_id"] = json!("7ecf0002-0000-4000-8000-000000000002");
            }),
            "subscription-state"
        ),
        "subscription.receiver_id is 7ecf0002-0000-4000-8000-000000000002, but a websocket Sender does not push \
         to a Receiver, so it names none"
    );
    let transport_file_message =
        |change: fn(&mut Value)| message(&with(|v| transport_file(v, change)), "manifest-transportfile");
    let at = format!(
        "in the one at http://192.168.10.21/x-nmos/connection/v1.1/single/senders/{AUDIO_SENDER}/transportfile"
    );
    assert_eq!(
        transport_file_message(|sdp| replace_in(sdp, "239.10.10.2", "239.10.10.9")),
        format!("stream 0 goes to 239.10.10.2:5006 in the SDP file at manifest_href, but to 239.10.10.9:5006 {at}")
    );
    assert_eq!(
        transport_file_message(|sdp| replace_in(sdp, "239.10.10.2 192.168.10.22", "239.10.10.2 192.168.10.23")),
        format!("stream 0 comes from 192.168.10.22 in the SDP file at manifest_href, but from 192.168.10.23 {at}")
    );
    assert_eq!(
        transport_file_message(|sdp| replace_in(sdp, "L24/48000/8", "L24/48000/2")),
        format!(
            "stream 0 is L24 48 kHz, 8 channels (51,ST), 1 ms, level A, 9.22 Mb/s in the SDP file at manifest_href, \
             but L24 48 kHz, 2 channels (51,ST), 1 ms, level A, 2.30 Mb/s {at}"
        )
    );
    assert_eq!(
        transport_file_message(|sdp| replace_in(sdp, "TSMODE=SAMP", "TSMODE=NEW")),
        format!("stream 0 has tsmode=SAMP in the SDP file at manifest_href, but tsmode=NEW {at}")
    );
    assert_eq!(
        transport_file_message(|sdp| replace_in(
            sdp,
            "a=mediaclk:direct=0\n",
            "a=mediaclk:direct=0\nm=audio 5008 RTP/AVP 97\nc=IN IP4 239.10.10.3/32\n"
        )),
        format!(
            "the SDP file at manifest_href has 1 stream, but the one at {} has 2 streams",
            &at["in the one at ".len()..]
        )
    );
    // Long lists are cut short.
    assert_eq!(
        message(
            &with(|v| {
                v["nodes"][0]["interfaces"] = (0..15).map(|i| json!({"name": format!("if{i}")})).collect();
                v["senders"][1]["interface_bindings"] = json!(["if3", "eth9", "eth9"]);
            }),
            "unknown-interface"
        ),
        "it binds to interface eth9, but its Node's interfaces are if0, if1, if2, if3, if4, if5, if6, if7, if8, \
         if9 and 5 more"
    );
}

/// Every resource in the facility, read through IS-04 v1.3 and known to be at it.
fn current(v: &mut Value) {
    let ids: Vec<Value> = ["nodes", "devices", "sources", "flows", "senders", "receivers"]
        .iter()
        .flat_map(|kind| v[kind].as_array().unwrap().iter().map(|r| r["id"].clone()).collect::<Vec<_>>())
        .collect();
    v["current"] = Value::Array(ids);
}

#[test]
fn resources_at_the_version_read_are_held_to_its_schema() {
    // The facility is complete at v1.3.
    let report = check(&with(current));
    assert_eq!(report.findings, [], "{:#?}", report.findings);
    let messages = |snapshot: &Snapshot| -> Vec<(&'static str, String)> {
        check(snapshot).findings.into_iter().map(|f| (f.rule, f.message)).collect()
    };
    let missing = with(|v| {
        current(v);
        v["nodes"][0].as_object_mut().unwrap().remove("interfaces");
        v["senders"][1].as_object_mut().unwrap().remove("tags");
    });
    assert_eq!(
        messages(&missing),
        [
            ("resource-invalid", "`interfaces` is missing, which IS-04 v1.3 requires".to_string()),
            ("resource-invalid", "`tags` is missing, which IS-04 v1.3 requires".to_string()),
        ]
    );
    // Unknown versions are held only to what every version requires.
    let unknown = with(|v| {
        current(v);
        v["current"].as_array_mut().unwrap().retain(|id| id != "a0de0001-0000-4000-8000-000000000001");
        v["nodes"][0].as_object_mut().unwrap().remove("interfaces");
    });
    assert_eq!(messages(&unknown), []);
    // An attribute every version requires is noted once, as it always was.
    let label = with(|v| {
        current(v);
        v["senders"][1].as_object_mut().unwrap().remove("label");
    });
    assert_eq!(messages(&label), [("resource-invalid", "`label` is missing".to_string())]);
    // Only a Node known to be at v1.3 is expected to say where its interfaces are plugged in.
    let unattached = |known: bool| {
        with(|v| {
            if known {
                current(v);
            }
            for i in 0..2 {
                v["nodes"][1]["interfaces"][i].as_object_mut().unwrap().remove("attached_network_device");
            }
        })
    };
    assert_eq!(
        messages(&unattached(true)),
        [(
            "interface-lldp",
            "interfaces eth0, eth1 give no attached_network_device, so nothing says which switch port they are \
             plugged into"
                .to_string()
        )]
    );
    assert_eq!(messages(&unattached(false)), []);
}

#[test]
fn interfaces_are_read_as_lldp_has_them() {
    let messages = |snapshot: &Snapshot| -> Vec<(&'static str, String)> {
        check(snapshot).findings.into_iter().map(|f| (f.rule, f.message)).collect()
    };
    assert_eq!(
        messages(&with(|v| v["nodes"][0]["interfaces"][0]["port_id"] = json!("C8:00:84:10:00:01"))),
        [(
            "resource-invalid",
            "`interfaces[0].port_id` is not a MAC address written lowercase with dashes, such as 00-1b-21-a1-b2-c3"
                .to_string()
        )]
    );
    assert_eq!(
        messages(&with(|v| v["nodes"][0]["interfaces"][0]["chassis_id"] = json!("C8:00:84:10:00:00"))),
        [(
            "interface-lldp",
            "interface eth0 has chassis_id C8:00:84:10:00:00; IS-04 writes a MAC address lowercase with dashes"
                .to_string()
        )]
    );
    // A chassis ID that is not a MAC address may be any text.
    assert_eq!(messages(&with(|v| v["nodes"][0]["interfaces"][0]["chassis_id"] = json!("cam1.studio"))), []);
    assert_eq!(
        messages(&with(|v| v["nodes"][0]["interfaces"][0]["attached_network_device"] = json!({"port_id": "1/1"}))),
        [("resource-invalid", "`interfaces[0].attached_network_device.chassis_id` is missing".to_string())]
    );
}

#[test]
fn constraint_sets_say_something() {
    let snapshot = with(|v| {
        v["receivers"][0]["caps"]["constraint_sets"]
            .as_array_mut()
            .unwrap()
            .push(json!({"urn:x-nmos:cap:meta:label": "anything", "urn:x-nmos:cap:meta:priority": 1}));
    });
    let findings = check(&snapshot).findings;
    let messages: Vec<(&str, &str)> = findings.iter().map(|f| (f.rule, f.message.as_str())).collect();
    assert_eq!(
        messages,
        [(
            "constraint-sets",
            "constraint set 2 holds no parameter constraint, so it says nothing about what the Receiver takes"
        )]
    );
}

#[test]
fn active_parameters_match_the_subscription() {
    let messages = |active: Value| -> Vec<String> {
        let snapshot = with(|v| v["active"] = active);
        check(&snapshot).findings.into_iter().filter(|f| f.rule == "active-subscription").map(|f| f.message).collect()
    };
    let agreeing = json!({
        VIDEO_RECEIVER: {"master_enable": true, "sender_id": VIDEO_SENDER, "transport_params": []},
        VIDEO_SENDER: {"master_enable": true, "receiver_id": null},
    });
    assert_eq!(messages(agreeing), Vec::<String>::new());
    assert_eq!(
        messages(json!({VIDEO_SENDER: {"master_enable": false, "receiver_id": null}})),
        ["subscription.active is true, but master_enable is false in its IS-05 /active"]
    );
    assert_eq!(
        messages(json!({VIDEO_RECEIVER: {"master_enable": true, "sender_id": null}})),
        [format!("subscription.sender_id is {VIDEO_SENDER}, but its IS-05 /active has sender_id null")]
    );
    assert_eq!(
        messages(json!({VIDEO_RECEIVER: {"master_enable": true, "sender_id": AUDIO_SENDER}})),
        [format!("subscription.sender_id is {VIDEO_SENDER}, but its IS-05 /active names {AUDIO_SENDER}")]
    );
}

#[test]
fn jpeg_xs_flows_match_profile_level_and_sublevel() {
    let jxsv = |change: fn(&mut Value)| {
        with(|v| {
            let flow = &mut v["flows"][0];
            flow["media_type"] = json!("video/jxsv");
            flow["grain_rate"] = json!({"numerator": 60000, "denominator": 1001});
            flow["profile"] = json!("High444.12");
            flow["level"] = json!("2k-1");
            flow["sublevel"] = json!("Sublev3bpp");
            v["manifests"][VIDEO_SENDER]["sdp"] = json!(include_str!("../../sdp/tests/fixtures/jpeg-xs.sdp"));
            change(v);
        })
    };
    let flow_sdp = |snapshot: &Snapshot| -> Vec<String> {
        check(snapshot).findings.into_iter().filter(|f| f.rule == "flow-sdp").map(|f| f.message).collect()
    };
    assert_eq!(flow_sdp(&jxsv(|_| {})), Vec::<String>::new());
    assert_eq!(
        flow_sdp(&jxsv(|v| v["flows"][0]["profile"] = json!("Main444.12"))),
        ["its Flow's profile is Main444.12, but profile is High444.12"]
    );
    assert_eq!(
        flow_sdp(&jxsv(|v| {
            v["flows"][0].as_object_mut().unwrap().remove("sublevel");
        })),
        ["its Flow has no sublevel, which means Unrestricted, but sublevel is Sublev3bpp"]
    );
    assert_eq!(
        flow_sdp(&jxsv(|v| replace_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], " level=2k-1;", ""))),
        ["its Flow's level is 2k-1, but its SDP file has no level"]
    );
    // The components describe JPEG XS as they do uncompressed video.
    assert_eq!(
        flow_sdp(&jxsv(|v| v["flows"][0]["components"][1]["width"] = json!(1920))),
        ["its Flow's components are YCbCr-4:4:4, but sampling is YCbCr-4:2:2"]
    );
}

/// The video Sender's ST 2022-7 pair in one media section with two SSRCs, as RFC 7104
/// allows, rather than two media sections.
fn one_media_section(v: &mut Value) {
    let sdp = v["manifests"][VIDEO_SENDER]["sdp"].as_str().unwrap();
    let (primary, _) = sdp.split_once("a=mid:primary\n").unwrap();
    let one = primary
        .replace("a=group:DUP primary secondary\n", "")
        .replace("192.168.10.21\n", "192.168.10.21 192.168.20.21\n");
    v["manifests"][VIDEO_SENDER]["sdp"] = json!(format!("{one}a=ssrc-group:DUP 1000 1010\n"));
}

#[test]
fn v1_0_flows_have_no_v1_1_defaults() {
    // A v1.0 Flow says nothing about interlacing or transfer characteristic, so an
    // interlaced HLG SDP file does not contradict it, nor can caps judge them.
    let snapshot = with(|v| {
        let v1_0 = ["id", "version", "label", "description", "tags", "source_id", "parents", "format"];
        v["flows"][0].as_object_mut().unwrap().retain(|key, _| v1_0.contains(&key.as_str()));
        replace_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], "TCS=SDR", "interlace; TCS=HLG");
        v["receivers"][0]["caps"]["constraint_sets"][0]["urn:x-nmos:cap:format:interlace_mode"] =
            json!({"enum": ["interlaced_tff", "interlaced_bff"]});
    });
    let findings = check(&snapshot).findings;
    let rules: Vec<(&str, &str)> = findings.iter().map(|f| (f.rule, f.message.as_str())).collect();
    assert!(!rules.iter().any(|(rule, _)| ["flow-sdp", "receiver-caps"].contains(rule)), "{rules:#?}");
    // A v1.1 Flow without interlace_mode is progressive.
    let snapshot = with(|v| {
        v["flows"][0].as_object_mut().unwrap().remove("interlace_mode");
        replace_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], "TCS=SDR", "interlace; TCS=SDR");
    });
    assert!(ids(&snapshot).contains("flow-sdp"));
}

#[test]
fn format_parameter_names_ignore_case() {
    let snapshot = with(|v| {
        v["flows"][0]["transfer_characteristic"] = json!("HLG");
        replace_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], "TCS=SDR", "tcs=HLG");
        replace_in(&mut v["manifests"][VIDEO_SENDER]["sdp"], "TP=2110TPN", "tp=2110TPN");
    });
    let rules = ids(&snapshot);
    assert!(!rules.contains("flow-sdp") && !rules.contains("sender-sdp"), "{rules:?}");
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
    // Both legs in one media section.
    let one = with(one_media_section);
    let rules: Vec<&str> = check(&one).findings.iter().map(|f| f.rule).filter(|r| r.contains("interface")).collect();
    assert!(rules.is_empty(), "{rules:?}");
    // Grandmasters that are both traceable to TAI keep the same time.
    clean(
        "traceable grandmasters",
        with(|v| {
            v["nodes"][1]["clocks"][0]["gmid"] = json!("ac-de-48-ff-fe-00-11-22");
            for node in 0..2 {
                v["nodes"][node]["clocks"][0]["traceable"] = json!(true);
            }
        }),
    );
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
    // A Connection API that serves the same streams, written differently.
    clean(
        "the same transport file",
        with(|v| {
            transport_file(v, |sdp| {
                replace_in(sdp, "\n", "\r\n");
                replace_in(
                    sdp,
                    "channel-order=SMPTE2110.(51,ST); TSMODE=SAMP",
                    "tsmode=SAMP; channel-order=SMPTE2110.(51,ST)",
                );
                replace_in(sdp, "o=- 1790510438 1790510438", "o=- 1790510438 1790510499");
            })
        }),
    );
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
