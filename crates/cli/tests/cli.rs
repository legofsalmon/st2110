//! The `st2110` binary: output, exit codes and formats.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdp/tests/fixtures");

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

fn st2110(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_st2110")).args(args).env("NO_COLOR", "1").output().expect("runs")
}

fn with_stdin_bytes(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_st2110"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runs");
    child.stdin.take().expect("stdin").write_all(input).expect("writes");
    child.wait_with_output().expect("finishes")
}

fn with_stdin(args: &[&str], input: &str) -> Output {
    with_stdin_bytes(args, input.as_bytes())
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8")
}

#[test]
fn clean_file_exits_zero_and_describes_its_streams() {
    let output = st2110(&["lint", &fixture("video-dup.sdp")]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("2 streams"), "{text}");
    assert!(
        text.contains("stream 1 (line 14, ST 2110-20, mid secondary) 239.20.10.1:5004: 1920x1080 progressive"),
        "{text}"
    );
    assert!(text.contains("no problems found"), "{text}");
}

#[test]
fn errors_exit_one_and_quote_the_line() {
    let output = st2110(&["lint", &fixture("aes67-offset.sdp")]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("aes67-offset.sdp:13: error[mediaclk-offset]: RTP clock offset 963214424"), "{text}");
    assert!(text.contains("  13 | a=mediaclk:direct=963214424"), "{text}");
    assert!(text.contains("1 error, 1 warning, 1 note"), "{text}");
}

#[test]
fn quiet_prints_only_problems() {
    let output = st2110(&["lint", "--quiet", &fixture("aes67-offset.sdp"), &fixture("video-dup.sdp")]);
    let text = stdout(&output);
    assert!(!text.contains("stream 0"), "{text}");
    assert!(!text.contains("tsmode-absent"), "{text}");
    assert!(!text.contains("video-dup.sdp"), "{text}");
    assert!(text.contains("error[mediaclk-offset]"), "{text}");
}

#[test]
fn warnings_fail_only_when_denied() {
    let sdp = std::fs::read_to_string(fixture("video-dup.sdp")).unwrap().replace("TP=2110TPN", "TP=2110TPW; TROFF=500");
    assert_eq!(with_stdin(&["lint", "-"], &sdp).status.code(), Some(0));
    let denied = with_stdin(&["lint", "--deny-warnings", "-"], &sdp);
    assert_eq!(denied.status.code(), Some(1));
    assert!(stdout(&denied).contains("-:10: warning[troff-nondefault]"), "{}", stdout(&denied));
}

#[test]
fn json_output() {
    let output = st2110(&["lint", "--format", "json", &fixture("aes67-offset.sdp"), &fixture("audio-pcm.sdp")]);
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let files = json.as_array().expect("an array per file");
    assert_eq!(files.len(), 2);
    assert!(files[0]["file"].as_str().unwrap().ends_with("aes67-offset.sdp"));
    let rules: Vec<&str> =
        files[0]["diagnostics"].as_array().unwrap().iter().map(|d| d["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["source-filter-missing", "tsmode-absent", "mediaclk-offset"]);
    let stream = &files[1]["streams"][0];
    assert_eq!(stream["essence"], "audio");
    assert_eq!(stream["channels"], 8);
    assert_eq!(stream["reference_clock"]["type"], "ptp");
    assert_eq!(stream["reference_clock"]["grandmaster"], "08-00-11-FF-FE-21-E1-B0");
    assert_eq!(stream["media_clock"], serde_json::json!({"type": "direct", "offset": 0}));
    assert_eq!(files[1]["diagnostics"], serde_json::json!([]));
}

#[test]
fn unreadable_file_exits_two() {
    let output = st2110(&["lint", &fixture("video-dup.sdp"), "no-such-file.sdp"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no-such-file.sdp"));
}

#[test]
fn rules_lists_and_explains() {
    let all = stdout(&st2110(&["rules"]));
    assert!(all.contains("mediaclk-offset error (ST 2110-10:2022 §7.3)"), "{all}");
    assert!(all.contains("ptp-unlocked warning (IS-04 v1.3 schemas)"), "{all}");
    let one = stdout(&st2110(&["rules", "tp-wide"]));
    assert_eq!(one.lines().count(), 2, "{one}");
    let registry = stdout(&st2110(&["rules", "receiver-caps"]));
    assert!(registry.starts_with("receiver-caps warning (BCP-004-01 v1.0"), "{registry}");
    let markdown = stdout(&st2110(&["rules", "--format", "markdown"]));
    assert_eq!(markdown, include_str!("../../../docs/rules.md"));
    let json: serde_json::Value =
        serde_json::from_slice(&st2110(&["rules", "--format", "json", "ssn"]).stdout).unwrap();
    assert_eq!(json[0]["severity"], "error");
    assert_eq!(st2110(&["rules", "no-such-rule"]).status.code(), Some(2));
    let ptp = stdout(&st2110(&["rules", "sm-jam-time"]));
    assert!(ptp.starts_with("sm-jam-time error (ST 2059-2:2021 Annex A)"), "{ptp}");
    // No identifier is in two catalogues.
    let every: serde_json::Value = serde_json::from_slice(&st2110(&["rules", "--format", "json"]).stdout).unwrap();
    let mut ids: Vec<&str> = every.as_array().unwrap().iter().map(|rule| rule["id"].as_str().unwrap()).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count);
}

const FACILITY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../nmos/tests/fixtures/facility.json");

/// The test facility with an unlocked clock on the monitor and an SDP error in the
/// audio Sender's file.
fn broken_facility() -> String {
    let mut facility: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(FACILITY).unwrap()).unwrap();
    facility["nodes"][1]["clocks"][0]["locked"] = false.into();
    let sdp = &mut facility["manifests"]["5e0d0002-0000-4000-8000-000000000002"]["sdp"];
    *sdp = sdp.as_str().unwrap().replace("direct=0", "direct=5").into();
    facility.to_string()
}

#[test]
fn nmos_lists_a_clean_registry() {
    let output = st2110(&["nmos", FACILITY]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for line in [
        "two-node test facility (IS-04 v1.3)",
        "  2 nodes, 2 devices, 2 sources, 2 flows, 2 senders (2 active), 2 receivers (2 active)",
        "  PTP: 2 clocks locked to 08-00-11-ff-fe-21-e1-b0",
        "  \"CAM 1 video\" (5e0d0001) on Camera 1: active, rtp.mcast, video/raw, 1 receiver",
        "    stream 1 (line 14, ST 2110-20, mid secondary) 239.20.10.1:5004: 1920x1080 progressive",
        "  \"MON 1 audio\" (7ecf0002) on Monitor 1: active, rtp.mcast, audio, from \"CAM 1 audio\" (5e0d0002)",
        "registry: no problems found",
    ] {
        assert!(text.contains(line), "no {line:?} in\n{text}");
    }
}

#[test]
fn nmos_reports_findings_and_quotes_sdp_lines() {
    let output = with_stdin(&["nmos", "-"], &broken_facility());
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("  PTP: 1 clock locked to 08-00-11-ff-fe-21-e1-b0; 1 clock unlocked"), "{text}");
    assert!(
        text.contains("node \"Monitor 1\" (a0de0002): warning[ptp-unlocked]: PTP clock clk0 is not locked"),
        "{text}"
    );
    assert!(
        text.contains("sender \"CAM 1 audio\" (5e0d0002), SDP line 12: error[mediaclk-offset]: RTP clock offset 5"),
        "{text}"
    );
    assert!(text.contains("    12 | a=mediaclk:direct=5"), "{text}");
    assert!(text.ends_with("registry: 1 error, 1 warning, 0 notes\n"), "{text}");

    let quiet = stdout(&with_stdin(&["nmos", "--quiet", "-"], &broken_facility()));
    assert!(!quiet.contains("senders:"), "{quiet}");
    assert!(quiet.starts_with("node \"Monitor 1\""), "{quiet}");
}

#[test]
fn nmos_json_and_exit_codes() {
    let output = with_stdin(&["nmos", "--format", "json", "-"], &broken_facility());
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json["summary"]["unlocked_clocks"], 1);
    assert_eq!(json["senders"][1]["streams"][0]["mid"], "primary");
    let rules: Vec<&str> = json["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["ptp-unlocked", "mediaclk-offset"]);
    assert_eq!(json["findings"][1]["resource"]["kind"], "sender");
    assert_eq!(json["findings"][1]["line"], 12);

    // A warning alone fails only when warnings are denied.
    let warning = broken_facility().replace("direct=5", "direct=0");
    assert_eq!(with_stdin(&["nmos", "-"], &warning).status.code(), Some(0));
    assert_eq!(with_stdin(&["nmos", "--deny-warnings", "-"], &warning).status.code(), Some(1));

    let missing = st2110(&["nmos", "no-such-snapshot.json"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no-such-snapshot.json"));
    let not_json = with_stdin(&["nmos", "-"], "v=0");
    assert_eq!(not_json.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&not_json.stderr).contains("not a registry snapshot"));
}

#[test]
fn nmos_saves_what_it_read() {
    let saved = std::env::temp_dir().join(format!("st2110-nmos-{}.json", std::process::id()));
    let output = st2110(&["nmos", "--quiet", "--save", saved.to_str().unwrap(), FACILITY]);
    assert_eq!(output.status.code(), Some(0));
    let original: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(FACILITY).unwrap()).unwrap();
    let copy: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&saved).unwrap()).unwrap();
    std::fs::remove_file(&saved).unwrap();
    assert_eq!(copy, original);
}

#[test]
fn nmos_unreachable_registry_exits_two() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let output = st2110(&["nmos", "--timeout", "2", &format!("http://127.0.0.1:{port}")]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("http://127.0.0.1:{port}/x-nmos/query/")), "{stderr}");
    assert_eq!(st2110(&["nmos", "--timeout", "0", "http://127.0.0.1:1"]).status.code(), Some(2));
}

#[test]
fn connect_lists_what_each_receiver_can_take() {
    let output = st2110(&["connect", FACILITY]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        "receiver \"MON 1 audio\" (7ecf0002)\n  sender \"CAM 1 audio\" (5e0d0002), taking it now\n\
         receiver \"MON 1 video\" (7ecf0001)\n  sender \"CAM 1 video\" (5e0d0001), taking it now\n"
    );
    let one = st2110(&["connect", FACILITY, "--receiver", "mon 1 video", "--format", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&one.stdout).expect("JSON");
    assert_eq!(json["receivers"].as_array().unwrap().len(), 1);
    assert_eq!(json["senders"][json["receivers"][0]["current"].as_u64().unwrap() as usize]["label"], "CAM 1 video");
}

#[test]
fn connect_refuses_what_it_cannot_read() {
    let stderr = |args: &[&str]| {
        let output = st2110(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        String::from_utf8(output.stderr).unwrap()
    };
    assert!(
        stderr(&["connect", FACILITY, "--receiver", "7ecf", "--disconnect"])
            .contains("2 receivers have an id starting 7ecf")
    );
    assert!(
        stderr(&["connect", FACILITY, "--receiver", "MON 1 video", "--sender", "CAM 9"])
            .contains("no sender has the id or label CAM 9")
    );
    assert!(
        stderr(&["connect", FACILITY, "--receiver", "MON 1 video", "--disconnect", "--at", "1:0"])
            .contains("--at 1:0 has passed")
    );
    assert!(
        stderr(&["connect", FACILITY, "--receiver", "MON 1 video", "--disconnect", "--at", "soon"])
            .contains("--at soon: not now")
    );
    let salvo = std::env::temp_dir().join(format!("st2110-salvo-{}.json", std::process::id()));
    std::fs::write(&salvo, r#"[{"receiver": "MON 1 video", "sender": "CAM 1 video", "disconnect": true}]"#).unwrap();
    let both = stderr(&["connect", FACILITY, "--salvo", salvo.to_str().unwrap()]);
    std::fs::write(&salvo, r#"{"receiver": "MON 1 video"}"#).unwrap();
    let not_a_list = stderr(&["connect", FACILITY, "--salvo", salvo.to_str().unwrap()]);
    std::fs::remove_file(&salvo).unwrap();
    assert!(both.ends_with("connection 1: give one of a sender, an SDP file or disconnect\n"), "{both}");
    assert!(not_a_list.contains("not a salvo: invalid type: map, expected a sequence"), "{not_a_list}");
}

/// A Connection API for the test facility's Receivers that activates each `PATCH` at
/// once, shows an activation scheduled on each, and serves the Senders' SDP files.
/// Returns its port.
fn connection_api() -> u16 {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read};
    use std::sync::{Arc, Mutex};

    let facility: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(FACILITY).unwrap()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let active: Arc<Mutex<BTreeMap<String, serde_json::Value>>> = Arc::default();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" || header.is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let path = request.split_whitespace().nth(1).unwrap().to_string();
            let parts: Vec<&str> = path.split('/').collect();
            let (status, body) = match (request.split_whitespace().next(), parts.as_slice()) {
                (Some("GET"), ["", "sdp", id]) => {
                    (200, facility["manifests"][*id]["sdp"].as_str().unwrap().to_string())
                }
                (Some("GET"), [.., id, "constraints"]) => {
                    let legs = if id.starts_with("7ecf0001") { 2 } else { 1 };
                    let leg = serde_json::json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {}, "destination_port": {}, "rtp_enabled": {}});
                    (200, serde_json::Value::Array(vec![leg; legs]).to_string())
                }
                (Some("GET"), [.., _, "staged"]) => {
                    let due = "1790510497:0";
                    let activation = serde_json::json!({"mode": "activate_scheduled_absolute", "requested_time": due, "activation_time": due});
                    (200, serde_json::json!({"activation": activation}).to_string())
                }
                (Some("GET"), [.., id, "active"]) => {
                    let idle = serde_json::json!({"sender_id": null, "master_enable": false, "transport_params": [{}]});
                    (200, active.lock().unwrap().get(*id).unwrap_or(&idle).to_string())
                }
                (Some("PATCH"), [.., id, "staged"]) => {
                    let mut staged: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    staged["activation"]["activation_time"] = "1790510437:0".into();
                    active.lock().unwrap().insert(id.to_string(), staged.clone());
                    (200, staged.to_string())
                }
                _ => (404, String::new()),
            };
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        }
    });
    port
}

/// The test facility as a saved snapshot, its Devices and SDP files served on `port`.
fn facility_on(port: u16) -> std::path::PathBuf {
    let mut facility: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(FACILITY).unwrap()).unwrap();
    for sender in facility["senders"].as_array_mut().unwrap() {
        sender["manifest_href"] = format!("http://127.0.0.1:{port}/sdp/{}", sender["id"].as_str().unwrap()).into();
    }
    for device in facility["devices"].as_array_mut().unwrap() {
        device["controls"][0]["href"] = format!("http://127.0.0.1:{port}/x-nmos/connection/v1.1/").into();
    }
    let path = std::env::temp_dir().join(format!("st2110-connect-{port}.json"));
    std::fs::write(&path, facility.to_string()).unwrap();
    path
}

#[test]
fn connect_plans_makes_and_refuses_connections() {
    let snapshot = facility_on(connection_api());
    let snapshot = snapshot.to_str().unwrap();
    let args = |extra: &[&'static str]| [&["connect", snapshot, "--receiver", "MON 1 video"], extra].concat();

    let planned = st2110(&args(&["--sender", "CAM 1 video", "--dry-run"]));
    assert_eq!(planned.status.code(), Some(0));
    assert_eq!(
        stdout(&planned),
        "receiver \"MON 1 video\" (7ecf0001) ← sender \"CAM 1 video\" (5e0d0001): planned\n\
         \x20 leg 1: 239.10.10.1:5004 from 192.168.10.21\n\
         \x20 leg 2: 239.20.10.1:5004 from 192.168.20.21\n\
         1 connection: 1 planned\n"
    );

    let done = st2110(&args(&["--sender", "CAM 1 video"]));
    assert_eq!(done.status.code(), Some(0), "{}", String::from_utf8_lossy(&done.stderr));
    let text = stdout(&done);
    assert!(text.starts_with("receiver \"MON 1 video\" (7ecf0001) ← sender \"CAM 1 video\" (5e0d0001): done at 2026-09-27 12:00:00.000000000 UTC\n"), "{text}");

    let refused = st2110(&args(&["--sender", "CAM 1 audio", "--format", "json"]));
    assert_eq!(refused.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&refused.stdout).expect("JSON");
    assert_eq!(json["connections"][0]["state"], "refused");
    assert_eq!(
        json["connections"][0]["problems"][0],
        "it is a video Receiver, but sender \"CAM 1 audio\" (5e0d0002) sends audio"
    );
    assert_eq!(json["connections"][0]["request"]["transport_params"][1], serde_json::json!({"rtp_enabled": false}));

    let cancelled = st2110(&args(&["--cancel"]));
    assert_eq!(cancelled.status.code(), Some(0));
    assert_eq!(
        stdout(&cancelled),
        "receiver \"MON 1 video\" (7ecf0001): cancelled the activation due at 2026-09-27 12:01:00.000000000 UTC\n"
    );
    std::fs::remove_file(snapshot).unwrap();
}

const PTP_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../ptp/tests/fixtures");

fn ptp_fixture(name: &str) -> String {
    format!("{PTP_FIXTURES}/{name}")
}

#[test]
fn ptp_describes_clean_messages() {
    let output = st2110(&["ptp", &ptp_fixture("grandmaster.hex")]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for line in [
        "grandmaster.hex:3: Announce from 08-00-11-FF-FE-21-E1-B0 port 1, domain 127, sequence 1, one a second",
        "  UTC offset 37 s (valid); PTP timescale, UTC offset valid, time traceable, frequency traceable",
        "  precise origin 1790510438.123457021, correction 1.500 ns",
        "  synchronization metadata: 30000/1001 fps drop-frame, externally locked, local offset 3563 s, \
         next jam 2026-09-28 00:00:00 Local Time, jump of -3600 s at 2026-10-25 02:00:00 Local Time",
        "grandmaster.hex: 5 messages, no problems found",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn ptp_reports_problems_and_undecodable_lines() {
    let output = st2110(&["ptp", "--quiet", &ptp_fixture("misconfigured.hex")]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(!text.contains("Announce from"), "{text}");
    for line in [
        "misconfigured.hex:3: warning[gm-clock-class]: grandmaster 08-00-11-FF-FE-21-E1-B0 has clockClass 248",
        "misconfigured.hex:5: error[sync-interval]: logMessageInterval is 0 (one a second), outside −7 to −1",
        "misconfigured.hex:7: error[sm-jam-time]: timeOfNextJam 1790550337 is 2026-09-28 00:05:00 Local Time",
        "misconfigured.hex:9: error: 40 octets, but the message needs 44",
        "misconfigured.hex:11: error: 'n' is not a hex digit",
        "misconfigured.hex: 5 messages, 4 errors, 2 warnings, 0 notes",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn ptp_reads_binary_and_writes_json() {
    let hex = std::fs::read_to_string(ptp_fixture("grandmaster.hex")).unwrap();
    let management = hex.lines().filter(|line| !line.starts_with('#')).nth(4).unwrap();
    let bytes: Vec<u8> =
        (0..management.len()).step_by(2).map(|i| u8::from_str_radix(&management[i..i + 2], 16).unwrap()).collect();
    let output = with_stdin_bytes(&["ptp", "--format", "json", "-"], &bytes);
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let entry = &json[0]["messages"][0];
    assert!(entry.get("line").is_none(), "{entry}");
    assert_eq!(entry["message"]["body"]["type"], "management");
    assert_eq!(entry["message"]["body"]["action"], "COMMAND");
    let content = &entry["message"]["tlvs"][0]["content"];
    assert_eq!(content["kind"], "sync_metadata");
    assert_eq!(content["locking_status"], "externally locked");
    assert_eq!(content["current_local_offset"], 3563);
    assert_eq!(entry["findings"], serde_json::json!([]));
}

#[test]
fn ptp_reads_text_whatever_its_comments_hold() {
    let hex = std::fs::read_to_string(ptp_fixture("grandmaster.hex")).unwrap();
    let sync = hex.lines().filter(|line| !line.starts_with('#')).nth(1).unwrap();
    for input in [format!("# Sync — two-step, 8 a second\n{sync}\n"), format!("\u{FEFF}{sync}\r\n")] {
        let output = with_stdin(&["ptp", "-"], &input);
        assert_eq!(output.status.code(), Some(0), "{input:?}");
        assert!(stdout(&output).contains("-: 1 message, no problems found"), "{}", stdout(&output));
    }
    let failed = |input: &[u8], expected: &str| {
        let output = with_stdin_bytes(&["ptp", "-"], input);
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout(&output).contains(expected), "{}", stdout(&output));
    };
    failed(b"", "-: error: no messages: give one message in hex per line, or one binary message");
    failed(b"# nothing yet\n\n", "-: 0 messages, 1 error, 0 warnings, 0 notes");
    failed(&[0xFF, 0xFE, b'0', 0], "-: error: the file is UTF-16 text");
    failed(&[0; 44], "-: error: read as one binary message, having control characters: PTP version 0");
}

#[test]
fn ptp_warnings_fail_only_when_denied() {
    let hex = std::fs::read_to_string(ptp_fixture("misconfigured.hex")).unwrap();
    let announce = hex.lines().nth(2).unwrap();
    assert_eq!(with_stdin(&["ptp", "-"], announce).status.code(), Some(0));
    assert_eq!(with_stdin(&["ptp", "--deny-warnings", "-"], announce).status.code(), Some(1));
    assert_eq!(st2110(&["ptp", "no-such-file.hex"]).status.code(), Some(2));
}

#[test]
fn time_at_an_instant() {
    let args = ["time", "--at", "2026-09-27T12:00:00.123456789Z", "--local-offset", "3563"];
    let output = st2110(&[&args[..], &["--video", "59.94", "--audio", "48000"]].concat());
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for line in [
        "PTP time    1790510437.123456789",
        "Local Time  2026-09-27 13:00:00.123456789 (offset 3563 s)",
        "video 60000/1001 (59.94 fps)",
        "  began       1790510437.115400000, RTP 3061361762 at 90 kHz",
        "  next        1790510437.132083334, RTP 3061363263",
        "  time code   13:00:00;04 (30000/1001 fps drop-frame, from the jam at 2026-09-27 00:00:00 Local Time)",
        "  RTP         2205388965 for a sample taken now",
        "  next block  1790510437.124000000",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn time_defaults_json_and_errors() {
    let output = st2110(&["time", "--at", "1790510437.123456789", "--format", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(json["local"], "2026-09-27 12:00:00.123456789");
    let rates: Vec<&str> = json["video"].as_array().unwrap().iter().map(|v| v["rate"].as_str().unwrap()).collect();
    assert_eq!(rates, ["50", "60000/1001"]);
    assert_eq!(json["video"][1]["timecode"]["address"], "12:00:00;04");
    assert_eq!(json["audio"][0]["rate"], 48000);
    let non_drop = st2110(&["time", "--at", "1790510437.123456789", "--video", "29.97", "--non-drop"]);
    assert!(stdout(&non_drop).contains("11:59:16:28 (30000/1001 fps, from the jam"), "{}", stdout(&non_drop));
    // The system clock when no time is given.
    assert_eq!(st2110(&["time"]).status.code(), Some(0));
    let bad = st2110(&["time", "--at", "noon"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("--at noon: not a PTP time"));
    assert_eq!(st2110(&["time", "--video", "fast"]).status.code(), Some(2));
    assert_eq!(st2110(&["time", "--at", "1790510437", "--jam", "1790510438"]).status.code(), Some(2));
}

#[test]
fn time_code_around_jams() {
    let timecode = |args: &[&str]| {
        let text = stdout(&st2110(&[&["time"], args].concat()));
        text.lines().find(|line| line.starts_with("  time code")).unwrap_or_default().to_string()
    };
    // The clocks went forward at 01:00 UTC; time code keeps the midnight jam's offset.
    let spring = ["--at", "2027-03-28T12:00:00Z", "--local-offset", "3563", "--video", "25"];
    assert_eq!(
        timecode(&[&spring[..], &["--jam-local-offset", "-37"]].concat()),
        "  time code   12:00:00:00 (25 fps, from the jam at 2027-03-28 00:00:00 Local Time)"
    );
    // Before the first 29.97 codeword after midnight, the jam the day before counts.
    assert_eq!(
        timecode(&["--at", "2026-09-27T00:00:00.010Z", "--video", "29.97"]),
        "  time code   00:00:00;02 (30000/1001 fps drop-frame, from the jam at 2026-09-26 00:00:00 Local Time)"
    );
    assert_eq!(
        timecode(&["--at", "2026-09-27T00:00:00.010Z", "--video", "29.97", "--jam", "2026-09-27T00:00:00Z"]),
        "  time code   none: no daily jam before the codeword in progress began"
    );
}

#[test]
fn time_refuses_what_it_cannot_work_out() {
    let refused = |args: &[&str], expected: &str| {
        let output = st2110(&[&["time"], args].concat());
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{stderr}");
    };
    refused(&["--tai-utc=-2147483648"], "-2147483648 is not in -86400..=86400");
    refused(&["--local-offset", "86401"], "86401 is not in -86400..=86400");
    refused(&["--at", "2026-09-27T12:00:00Z", "--jam", "2026-09-27T00:00:00.5Z"], "falls on a whole second");
    refused(
        &["--at", "281474976710655.999999999", "--video", "25"],
        "the next frame or block would begin after the last PTP time",
    );
}

/// 2026-09-27 12:00:00 UTC in PTP seconds.
const NOON: u64 = 1_790_510_437;

/// An Ethernet frame of 1 ms of 8-channel L24 audio from 192.168.10.22:5006 to
/// 239.10.10.2:5006, the stream in audio-pcm.sdp.
fn audio_frame(payload_type: u8, ssrc: u32, seq: u16, timestamp: u32) -> Vec<u8> {
    let mut rtp = vec![0x80, payload_type];
    rtp.extend(seq.to_be_bytes());
    rtp.extend(timestamp.to_be_bytes());
    rtp.extend(ssrc.to_be_bytes());
    rtp.extend([0x11; 48 * 3 * 8]);
    let mut frame = vec![0x01, 0x00, 0x5E, 0x0A, 0x0A, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    frame.extend([0x45, 0xB8]);
    frame.extend(((20 + 8 + rtp.len()) as u16).to_be_bytes());
    frame.extend([0, 1, 0x40, 0, 64, 17, 0, 0, 192, 168, 10, 22, 239, 10, 10, 2]);
    frame.extend(5006_u16.to_be_bytes());
    frame.extend(5006_u16.to_be_bytes());
    frame.extend(((8 + rtp.len()) as u16).to_be_bytes());
    frame.extend([0, 0]);
    frame.extend(rtp);
    frame
}

/// A pcap file of 200 ms of that audio from noon, PTP time, each packet arriving 150 µs
/// after its last sample. `packet` makes packet `i` from its first sample's timestamp.
fn audio_capture(packet: impl Fn(u16, u32) -> Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
    for i in 0..200 {
        let millisecond = NOON * 1000 + i;
        let arrival = (millisecond + 1) * 1_000_000 + 150_000;
        let frame = packet(i as u16, (millisecond * 48) as u32);
        out.extend(((arrival / 1_000_000_000) as u32).to_le_bytes());
        out.extend(((arrival % 1_000_000_000) as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend(frame);
    }
    out
}

fn clean_audio() -> Vec<u8> {
    audio_capture(|i, timestamp| audio_frame(97, 0x2222_0002, i, timestamp))
}

#[test]
fn pcap_measures_a_capture_against_its_sdp_file() {
    let sdp = fixture("audio-pcm.sdp");
    let output = with_stdin_bytes(&["pcap", "-", "--sdp", &sdp], &clean_audio());
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    let expected = [
        "-: pcap (nanosecond), 200 frames in 0.199 s: 200 RTP packets in 1 flow, 0 PTP messages".to_string(),
        "  clock: PTP time: with no PTP Sync messages to go by, the timestamps of 1 of 1 RTP flow sit within half a second of PTP time".to_string(),
        format!("  flow 1: 192.168.10.22:5006 to 239.10.10.2:5006, ST 2110-30, {sdp} stream 0"),
        "    200 packets (payload type 97, SSRC 22220002) at 9.5 Mb/s".to_string(),
        "    audio: L24, 48000 Hz, 8 channels, 48 samples a packet (1000.0 µs)".to_string(),
        "    latency 1150.0 µs (1150.0 to 1150.0), packet interval 1000.0 µs (1000.0 to 1000.0), TS-DF at most 0.0 µs".to_string(),
        "-: 1 flow, no problems found".to_string(),
    ];
    assert_eq!(text, format!("{}\n\n", expected.join("\n")));
}

#[test]
fn pcap_reports_findings_with_where_and_when() {
    let sdp = fixture("audio-pcm.sdp");
    let wrong_type = audio_capture(|i, timestamp| audio_frame(98, 0x2222_0002, i, timestamp));
    let output = with_stdin_bytes(&["pcap", "--quiet", "-", "--sdp", &sdp], &wrong_type);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stdout(&output),
        "-: flow 1 at 0.000 s: error[payload-type-mismatch]: 200 packets carried payload type 98, not the 97 of \
         the SDP file's m= line (RFC 3550 §5.1 · RFC 8866 §5.14)\n\
         -: 1 flow, 1 error, 0 warnings, 0 notes\n"
    );
    // A new SSRC is a warning, which fails only when warnings are denied.
    let new_ssrc =
        audio_capture(|i, timestamp| audio_frame(97, if i < 100 { 0x2222_0002 } else { 0x2222_0099 }, i, timestamp));
    assert_eq!(with_stdin_bytes(&["pcap", "-", "--sdp", &sdp], &new_ssrc).status.code(), Some(0));
    let denied = with_stdin_bytes(&["pcap", "--deny-warnings", "-", "--sdp", &sdp], &new_ssrc);
    assert_eq!(denied.status.code(), Some(1));
    let text = stdout(&denied);
    assert!(text.contains("-: flow 1 at 0.100 s: warning[ssrc-change]: the SSRC changed 1 time"), "{text}");
}

#[test]
fn pcap_recognises_flows_and_writes_json() {
    let output = with_stdin_bytes(&["pcap", "--format", "json", "-"], &clean_audio());
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let report = &json[0];
    assert_eq!((report["file"].as_str(), report["capture"]["format"].as_str()), (Some("-"), Some("pcap (nanosecond)")));
    assert_eq!(report["timescale"]["clock"], "ptp");
    let flow = &report["flows"][0];
    assert_eq!((flow["essence"].as_str(), flow["guessed"].as_bool()), (Some("audio"), Some(true)));
    assert_eq!((flow["audio"]["encoding"].as_str(), flow["audio"]["channels"].as_u64()), (Some("L24"), Some(8)));
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn pcap_timescale_can_be_chosen() {
    let text = stdout(&with_stdin_bytes(&["pcap", "--timescale", "utc", "--tai-utc", "36", "-"], &clean_audio()));
    assert!(
        text.contains("  clock: UTC, moved 36 s onto PTP time: chosen, not worked out from the capture\n"),
        "{text}"
    );
    assert!(text.contains("latency 36001150.0 µs"), "{text}");
}

#[test]
fn pcap_exit_codes_for_files_it_cannot_read_to_the_end() {
    let not_a_capture = with_stdin_bytes(&["pcap", "-"], b"v=0\r\n");
    assert_eq!(not_a_capture.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&not_a_capture.stderr);
    assert!(stderr.contains("st2110: -: not a pcap or pcapng file"), "{stderr}");
    let missing = st2110(&["pcap", "no-such-file.pcap"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("st2110: no-such-file.pcap: "));
    // Without its SDP file, a capture is not analysed at all.
    let missing_sdp = st2110(&["pcap", "no-such-file.pcap", "--sdp", "no-such-file.sdp"]);
    assert_eq!(missing_sdp.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_sdp.stderr).contains("st2110: no-such-file.sdp: "));
    let mut truncated = clean_audio();
    truncated.truncate(truncated.len() - 10);
    let output = with_stdin_bytes(&["pcap", "-"], &truncated);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("-: error: the file ends partway through a packet; the analysis stops there\n"), "{text}");
    assert!(text.ends_with("-: 1 flow, 1 error, 0 warnings, 0 notes\n\n"), "{text}");
}
