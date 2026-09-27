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

fn with_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_st2110"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runs");
    child.stdin.take().expect("stdin").write_all(input.as_bytes()).expect("writes");
    child.wait_with_output().expect("finishes")
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
    let one = stdout(&st2110(&["rules", "tp-wide"]));
    assert_eq!(one.lines().count(), 2, "{one}");
    let markdown = stdout(&st2110(&["rules", "--format", "markdown"]));
    assert_eq!(markdown, include_str!("../../../docs/rules.md"));
    let json: serde_json::Value =
        serde_json::from_slice(&st2110(&["rules", "--format", "json", "ssn"]).stdout).unwrap();
    assert_eq!(json[0]["severity"], "error");
    assert_eq!(st2110(&["rules", "no-such-rule"]).status.code(), Some(2));
}
