//! Finding Senders and Receivers, their Connection APIs, and which Senders each
//! Receiver can take, in the two-node test facility.

use serde_json::{Value, json};
use st2110_nmos::routing::{self, ConnectionApi};
use st2110_nmos::{Kind, Snapshot};

const FACILITY: &str = include_str!("fixtures/facility.json");

const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const AUDIO_SENDER: &str = "5e0d0002-0000-4000-8000-000000000002";
const VIDEO_RECEIVER: &str = "7ecf0001-0000-4000-8000-000000000001";
const AUDIO_RECEIVER: &str = "7ecf0002-0000-4000-8000-000000000002";

fn with(change: impl FnOnce(&mut Value)) -> Snapshot {
    let mut value: Value = serde_json::from_str(FACILITY).expect("the fixture is JSON");
    change(&mut value);
    serde_json::from_value(value).expect("still a snapshot")
}

#[test]
fn finds_by_id_label_or_the_start_of_the_id() {
    let snapshot = with(|_| {});
    for selector in [VIDEO_RECEIVER, "7ECF0001-0000-4000-8000-000000000001", "mon 1 video", " MON 1 video ", "7ecf0001"]
    {
        let found = routing::find(&snapshot, Kind::Receiver, selector).expect(selector);
        assert_eq!(found.id, VIDEO_RECEIVER, "{selector}");
    }
    let receiver = routing::find(&snapshot, Kind::Receiver, "MON 1 video").unwrap();
    assert_eq!(receiver.describe(), "receiver \"MON 1 video\" (7ecf0001)");
    assert_eq!((receiver.node.as_deref(), receiver.device.as_deref()), (Some("Monitor 1"), Some("Monitor 1")));
    assert_eq!(receiver.format.as_deref(), Some("urn:x-nmos:format:video"));
    assert_eq!(receiver.transport.as_deref(), Some("urn:x-nmos:transport:rtp.mcast"));
    assert_eq!((receiver.active, receiver.subscription.as_deref()), (Some(true), Some(VIDEO_SENDER)));
    assert_eq!(receiver.version.as_deref(), Some("1790510437:0"));
    assert_eq!(
        receiver.connection_api,
        Some(ConnectionApi { version: "v1.1".into(), href: "http://192.168.10.31/x-nmos/connection/v1.1/".into() })
    );

    let sender = routing::find(&snapshot, Kind::Sender, "CAM 1 audio").unwrap();
    assert_eq!(sender.id, AUDIO_SENDER);
    assert_eq!(sender.format.as_deref(), Some("urn:x-nmos:format:audio"), "from its Flow");
    assert!(sender.manifest_href.as_deref().is_some_and(|href| href.ends_with("/transportfile")));
    assert_eq!((sender.active, sender.subscription.as_deref()), (Some(true), None));
}

#[test]
fn lists_senders_in_label_order() {
    let snapshot = with(|value| {
        // A Sender with no id cannot be named, so is not listed.
        let mut nameless = value["senders"][0].clone();
        nameless.as_object_mut().unwrap().remove("id");
        value["senders"].as_array_mut().unwrap().push(nameless);
    });
    let senders = routing::senders(&snapshot);
    let listed: Vec<(&str, &str)> = senders.iter().map(|s| (s.label.as_str(), s.id.as_str())).collect();
    assert_eq!(listed, [("CAM 1 audio", AUDIO_SENDER), ("CAM 1 video", VIDEO_SENDER)]);
    assert!(senders.iter().all(|s| s.kind == Kind::Sender && s.node.as_deref() == Some("Camera 1")));
}

#[test]
fn says_why_a_name_finds_nothing_or_too_much() {
    let snapshot = with(|_| {});
    let error = |kind, selector| routing::find(&snapshot, kind, selector).unwrap_err();
    assert_eq!(error(Kind::Receiver, "MON 9"), "no receiver has the id or label MON 9");
    assert_eq!(
        error(Kind::Receiver, "7ecf"),
        "2 receivers have an id starting 7ecf: receiver \"MON 1 audio\" (7ecf0002), receiver \"MON 1 video\" \
         (7ecf0001); name one by its id"
    );
    assert_eq!(error(Kind::Sender, "  "), "no sender was named");
    assert_eq!(error(Kind::Flow, "CAM 1 video"), "only Senders and Receivers are connected, not a flow");
    // A Sender's name finds no Receiver.
    assert_eq!(error(Kind::Receiver, "CAM 1 video"), "no receiver has the id or label CAM 1 video");

    let twins = with(|v| v["receivers"][1]["label"] = json!("MON 1 VIDEO"));
    let error = routing::find(&twins, Kind::Receiver, "mon 1 video").unwrap_err();
    assert!(error.starts_with("2 receivers are labelled mon 1 video: "), "{error}");
    // An exact id wins over a label that happens to match another.
    let named_after = with(|v| v["receivers"][1]["label"] = json!(VIDEO_RECEIVER));
    assert_eq!(routing::find(&named_after, Kind::Receiver, VIDEO_RECEIVER).unwrap().label, "MON 1 video");
}

#[test]
fn picks_the_newest_v1_connection_api() {
    let controls = |controls: Value| {
        let snapshot = with(|v| v["devices"][1]["controls"] = controls);
        routing::find(&snapshot, Kind::Receiver, "MON 1 video").unwrap().connection_api
    };
    let api = |version: &str, href: &str| Some(ConnectionApi { version: version.into(), href: href.into() });
    assert_eq!(
        controls(json!([
            {"type": "urn:x-nmos:control:sr-ctrl/v1.0", "href": "http://mon1/x-nmos/connection/v1.0/"},
            {"type": "urn:x-nmos:control:sr-ctrl/v1.2", "href": "http://mon1/x-nmos/connection/v1.2"},
            {"type": "urn:x-nmos:control:sr-ctrl/v1.10", "href": "ftp://mon1/x-nmos/connection/v1.10/"},
            {"type": "urn:x-nmos:control:sr-ctrl/v2.0", "href": "http://mon1/x-nmos/connection/v2.0/"},
            {"type": "urn:x-manufacturer:control:thing", "href": "http://mon1/thing/"},
        ])),
        api("v1.2", "http://mon1/x-nmos/connection/v1.2/"),
        "v1.10 has no HTTP URL and v2.0 is a different API"
    );
    assert_eq!(
        controls(json!([{"type": "urn:x-nmos:control:sr-ctrl/v1.1", "href": "https://mon1:8443/x-nmos/connection"}])),
        api("v1.1", "https://mon1:8443/x-nmos/connection/v1.1/"),
        "an href without the version gets it added"
    );
    assert_eq!(controls(json!([])), None);
    // An IS-04 v1.0 Device has no controls.
    let snapshot = with(|v| {
        v["devices"][1].as_object_mut().unwrap().remove("controls");
    });
    assert_eq!(routing::find(&snapshot, Kind::Receiver, "MON 1 video").unwrap().connection_api, None);
}

#[test]
fn routes_follow_transport_format_and_caps() {
    let snapshot = with(|_| {});
    assert_eq!(routing::route(&snapshot, VIDEO_SENDER, VIDEO_RECEIVER, None), Ok(()));
    assert_eq!(routing::route(&snapshot, AUDIO_SENDER, AUDIO_RECEIVER, None), Ok(()));
    assert_eq!(
        routing::route(&snapshot, AUDIO_SENDER, VIDEO_RECEIVER, None).unwrap_err(),
        "it is a video Receiver, but sender \"CAM 1 audio\" (5e0d0002) sends audio"
    );
    let unicast = with(|v| v["receivers"][0]["transport"] = json!("urn:x-nmos:transport:rtp.ucast"));
    assert_eq!(
        routing::route(&unicast, VIDEO_SENDER, VIDEO_RECEIVER, None).unwrap_err(),
        "it receives rtp.ucast, but sender \"CAM 1 video\" (5e0d0001) sends rtp.mcast"
    );
    // The Receiver's constraint sets ask for 2110TPN. Without the Sender's
    // st2110_21_sender_type, the SDP file's TP is what they judge.
    let wide = with(|v| {
        v["senders"][0].as_object_mut().unwrap().remove("st2110_21_sender_type");
        let sdp = v["manifests"][VIDEO_SENDER]["sdp"].as_str().unwrap().replace("TP=2110TPN", "TP=2110TPW");
        v["manifests"][VIDEO_SENDER]["sdp"] = json!(sdp);
    });
    let error = routing::route(&wide, VIDEO_SENDER, VIDEO_RECEIVER, None).unwrap_err();
    assert!(error.contains("st2110_21_sender_type 2110TPW is not one of 2110TPN"), "{error}");
    // An SDP file given for the Sender is judged in place of the one the snapshot holds.
    let fetched = snapshot.manifests[VIDEO_SENDER].sdp.as_deref();
    assert_eq!(routing::route(&wide, VIDEO_SENDER, VIDEO_RECEIVER, fetched), Ok(()));
    assert_eq!(
        routing::route(&snapshot, "0badbeef-0000-4000-8000-000000000000", VIDEO_RECEIVER, None).unwrap_err(),
        "sender 0badbeef-0000-4000-8000-000000000000 is not registered"
    );
    // Without a Flow nothing is known that would stand in the way.
    let flowless = with(|v| v["senders"][1]["flow_id"] = Value::Null);
    assert_eq!(routing::route(&flowless, AUDIO_SENDER, VIDEO_RECEIVER, None), Ok(()));
}

#[test]
fn routes_from_an_sdp_file_follow_transport_format_and_media_type() {
    let snapshot = with(|_| {});
    let sdp = |id: &str| snapshot.manifests[id].sdp.clone().unwrap();
    let (video, audio) = (sdp(VIDEO_SENDER), sdp(AUDIO_SENDER));
    let route = |sdp: &str, receiver| routing::route_sdp(&snapshot, sdp, receiver);
    assert_eq!(route(&video, VIDEO_RECEIVER), Ok(()));
    assert_eq!(route(&audio, AUDIO_RECEIVER), Ok(()));
    assert_eq!(route(&audio, VIDEO_RECEIVER).unwrap_err(), "it is a video Receiver, but the SDP file describes audio");
    assert_eq!(
        route(&video.replace("239.10.10.1/32", "192.168.10.31"), VIDEO_RECEIVER).unwrap_err(),
        "it receives rtp.mcast, but the SDP file describes rtp.ucast"
    );
    assert_eq!(
        route(&video.replace("raw/90000", "jxsv/90000"), VIDEO_RECEIVER).unwrap_err(),
        "its caps.media_types (video/raw) leave out video/jxsv, which the SDP file describes"
    );
    // Ancillary data is carried as video/smpte291, but it is data, not video.
    assert_eq!(
        route(&video.replace("raw/90000", "smpte291/90000"), VIDEO_RECEIVER).unwrap_err(),
        "it is a video Receiver, but the SDP file describes data"
    );
    assert_eq!(route("v=0\r\n", VIDEO_RECEIVER), Ok(()), "nothing is known that would stand in the way");
    assert_eq!(
        route(&video, "0badbeef-0000-4000-8000-000000000000").unwrap_err(),
        "receiver 0badbeef-0000-4000-8000-000000000000 is not registered"
    );
}

#[test]
fn the_matrix_lists_what_each_receiver_can_take() {
    let matrix = routing::matrix(&with(|_| {}));
    let labels: Vec<&str> = matrix.senders.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["CAM 1 audio", "CAM 1 video"]);
    let rows: Vec<(&str, &[usize], Option<usize>)> =
        matrix.receivers.iter().map(|r| (r.receiver.label.as_str(), r.fits.as_slice(), r.current)).collect();
    assert_eq!(rows, [("MON 1 audio", &[0][..], Some(0)), ("MON 1 video", &[1][..], Some(1))]);

    // A Receiver that takes any audio or video, and is idle.
    let open = with(|v| {
        let receiver = v["receivers"][1].as_object_mut().unwrap();
        receiver.remove("format");
        receiver.remove("caps");
        receiver["subscription"] = json!({"sender_id": null, "active": false});
    });
    let matrix = routing::matrix(&open);
    assert_eq!((matrix.receivers[0].fits.as_slice(), matrix.receivers[0].current), (&[0, 1][..], None));
    let json = serde_json::to_value(&matrix).unwrap();
    assert_eq!(json["receivers"][0]["receiver"]["kind"], "receiver");
    assert_eq!(json["senders"][1]["id"], VIDEO_SENDER);
}
