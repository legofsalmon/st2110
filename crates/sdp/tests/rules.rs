//! Every rule in the catalogue, raised by a small change to a clean fixture, and
//! the valid descriptions that must not raise it.

use std::collections::BTreeSet;

use st2110_sdp::{Severity, lint, rules};

const VIDEO: &str = include_str!("fixtures/video-dup.sdp");
const AUDIO: &str = include_str!("fixtures/audio-pcm.sdp");
const AES3: &str = include_str!("fixtures/aes3.sdp");
const ANC: &str = include_str!("fixtures/anc.sdp");
const JPEG_XS: &str = include_str!("fixtures/jpeg-xs.sdp");
const FMX: &str = include_str!("fixtures/fmx.sdp");
const TTML: &str = include_str!("fixtures/ttml.sdp");
const RFC4175: &str = include_str!("fixtures/rfc4175.sdp");

const REFCLK: &str = "a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127\n";
const FIRST_FILTER: &str = "a=source-filter: incl IN IP4 239.10.10.1 192.168.10.21";

/// Replaces every occurrence of `from`, which must be present.
fn with(base: impl AsRef<str>, from: &str, to: &str) -> String {
    let base = base.as_ref();
    assert!(base.contains(from), "the fixture has no {from:?}");
    base.replace(from, to)
}

/// Replaces only the first occurrence, to change one leg of the redundant pair.
fn with_first(base: impl AsRef<str>, from: &str, to: &str) -> String {
    let base = base.as_ref();
    assert!(base.contains(from), "the fixture has no {from:?}");
    base.replacen(from, to, 1)
}

fn ids(text: &str) -> BTreeSet<&'static str> {
    lint(text).diagnostics.iter().map(|d| d.rule).collect()
}

/// One description per rule that raises it.
fn cases() -> Vec<(&'static str, String)> {
    vec![
        // RFC 8866 structure.
        ("sdp-syntax", with(VIDEO, "s=CAM 1 video", "s = CAM 1 video")),
        ("sdp-blank-line", with(VIDEO, "t=0 0\n", "t=0 0\n\n")),
        ("sdp-unknown-type", with(VIDEO, "t=0 0\n", "t=0 0\nx=unknown\n")),
        ("sdp-order", with(VIDEO, "s=CAM 1 video\nt=0 0", "t=0 0\ns=CAM 1 video")),
        ("sdp-version", with(VIDEO, "v=0", "v=1")),
        ("sdp-required-line", with(VIDEO, "s=CAM 1 video\n", "")),
        ("sdp-duplicate-line", with(VIDEO, "s=CAM 1 video\n", "s=CAM 1 video\ns=CAM 2 video\n")),
        ("sdp-origin", with(VIDEO, "o=- 1790510437 1790510437", "o=- first 1790510437")),
        ("sdp-session-name", with(VIDEO, "s=CAM 1 video", "s=")),
        ("sdp-timing", with(VIDEO, "t=0 0", "t=now")),
        ("sdp-media-line", with(VIDEO, "m=video 5004 RTP/AVP 96", "m=video RTP/AVP 96")),
        ("sdp-connection", with(VIDEO, "c=IN IP4 239.10.10.1/32\n", "")),
        ("sdp-multicast-ttl", with(VIDEO, "239.10.10.1/32", "239.10.10.1")),
        ("sdp-bandwidth", with(VIDEO, "c=IN IP4 239.10.10.1/32\n", "c=IN IP4 239.10.10.1/32\nb=AS\n")),
        ("sdp-duplicate-attribute", with(VIDEO, "a=mid:primary\n", "a=mid:primary\na=mid:first\n")),
        ("media-disabled", with(VIDEO, "m=video 5004", "m=video 0")),
        // RTP.
        ("rtp-profile", with(VIDEO, "RTP/AVP 96", "RTP/SAVP 96")),
        (
            "rtp-payload-type",
            with(with(with(VIDEO, "RTP/AVP 96", "RTP/AVP 33"), ":96 raw", ":33 raw"), ":96 samp", ":33 samp"),
        ),
        ("rtp-single-format", with(VIDEO, "RTP/AVP 96", "RTP/AVP 96 97")),
        ("rtp-clock-rate", with(VIDEO, "raw/90000", "raw/48000")),
        ("rtpmap-missing", with(VIDEO, "a=rtpmap:96 raw/90000\n", "")),
        ("rtpmap-syntax", with(VIDEO, "a=rtpmap:96 raw/90000", "a=rtpmap:96 raw")),
        ("format-unlisted", with(VIDEO, "a=rtpmap:96 raw/90000\n", "a=rtpmap:96 raw/90000\na=rtpmap:98 raw/90000\n")),
        // Format parameters.
        ("fmtp-syntax", with(VIDEO, "width=1920; height=1080", "width=1920 height=1080")),
        ("fmtp-duplicate-param", with(VIDEO, "depth=10;", "depth=10; depth=10;")),
        ("fmtp-param-case", with(VIDEO, "sampling=", "Sampling=")),
        ("fmtp-quoted-value", with(VIDEO, "SSN=ST2110-20:2017", "SSN=\"ST2110-20:2017\"")),
        ("fmtp-unknown-param", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; fancy=1")),
        ("param-missing", with(VIDEO, "PM=2110GPM; ", "")),
        ("param-value", with(VIDEO, "colorimetry=BT709", "colorimetry=BT999")),
        ("frame-rate", with(VIDEO, "exactframerate=50", "exactframerate=50.0")),
        ("frame-rate-form", with(VIDEO, "exactframerate=50", "exactframerate=50/1")),
        ("ssn", with(VIDEO, "SSN=ST2110-20:2017", "SSN=ST2110-20:2022")),
        ("ssn-typo", with(ANC, "SSN=ST2110-40:2023", "SSN=ST2110-40:2021")),
        // ST 2110-10 clocks.
        ("ts-refclk-missing", with(VIDEO, REFCLK, "")),
        ("ts-refclk-syntax", with(VIDEO, "E1-B0:127", "E1-B0:999")),
        ("ts-refclk-not-ptp", with(VIDEO, "IEEE1588-2008", "IEEE1588-2002")),
        ("ts-refclk-ptp-version", with(VIDEO, "IEEE1588-2008", "IEEE1588-2019")),
        ("ts-refclk-domain", with(VIDEO, "E1-B0:127", "E1-B0:200")),
        (
            "ts-refclk-localmac",
            with(VIDEO, "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127", "localmac=CA-FE-01-CA-FE-02"),
        ),
        ("mediaclk-missing", with(VIDEO, "a=mediaclk:direct=0\n", "")),
        ("mediaclk-value", with(VIDEO, "direct=0", "direct=soon")),
        ("mediaclk-offset", with(VIDEO, "direct=0", "direct=5")),
        ("mediaclk-offset-implicit", with(VIDEO, "direct=0", "direct")),
        ("mediaclk-sender", with(VIDEO, "mediaclk:direct=0", "mediaclk:sender")),
        ("clock-session-level", with(with(VIDEO, REFCLK, ""), "a=group:DUP", &format!("{REFCLK}a=group:DUP"))),
        // ST 2110-10 addressing and shared parameters.
        ("source-filter-missing", with(VIDEO, &format!("{FIRST_FILTER}\n"), "")),
        (
            "source-filter-syntax",
            with(VIDEO, "source-filter: incl IN IP4 239.10.10.1", "source-filter: include IN IP4 239.10.10.1"),
        ),
        ("source-filter-mismatch", with(VIDEO, FIRST_FILTER, "a=source-filter: incl IN IP4 239.10.10.9 192.168.10.21")),
        ("maxudp", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; MAXUDP=9000")),
        ("maxudp-extended", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; MAXUDP=8960")),
        ("tsmode", with(VIDEO, "TSMODE=SAMP", "TSMODE=FIRST")),
        ("tsmode-absent", with(VIDEO, "; TSMODE=SAMP", "")),
        ("tsdelay", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; TSDELAY=soon")),
        // Groups.
        ("group-syntax", with(VIDEO, "a=group:DUP primary secondary", "a=group:DUP")),
        ("group-mid-missing", with(VIDEO, "a=group:DUP primary secondary", "a=group:DUP primary tertiary")),
        ("mid-duplicate", with(VIDEO, "a=mid:secondary", "a=mid:primary")),
        ("dup-group", with(VIDEO, "a=group:DUP primary secondary", "a=group:DUP primary")),
        ("dup-mismatch", with_first(VIDEO, "exactframerate=50", "exactframerate=25")),
        ("dup-addressing", with(with(VIDEO, "239.20.10.1", "239.10.10.1"), "192.168.20.21", "192.168.10.21")),
        ("dup-refclk", with_first(VIDEO, "E1-B0:127", "E1-B0:126")),
        ("multistream-deprecated", with(VIDEO, "a=group:DUP", "a=group:MULTI-SD")),
        ("multistream-count", with(VIDEO, "a=group:DUP", "a=group:MULTI-2SI")),
        ("multistream-addresses", with(with(VIDEO, "a=group:DUP", "a=group:MULTI-2SI"), "239.20.10.1", "239.10.10.1")),
        ("multistream-format", with_first(with(VIDEO, "a=group:DUP", "a=group:PHASED"), "depth=10", "depth=12")),
        (
            "multistream-troff",
            with_first(with(VIDEO, "a=group:DUP", "a=group:MULTI-2SI"), "TSMODE=SAMP", "TSMODE=SAMP; TROFF=500"),
        ),
        (
            "multistream-phased-troff",
            with_first(with(VIDEO, "a=group:DUP", "a=group:PHASED"), "TSMODE=SAMP", "TSMODE=SAMP; TROFF=500"),
        ),
        (
            "multistream-dup",
            with(VIDEO, "a=group:DUP primary secondary", "a=group:PHASED primary secondary\na=group:DUP primary"),
        ),
        (
            "fid-anc",
            with(
                with(ANC, "t=0 0\n", "t=0 0\na=group:FID anc\n"),
                "a=mediaclk:direct=0\n",
                "a=mediaclk:direct=0\na=mid:anc\n",
            ),
        ),
        // ST 2110-20 video, ST 2110-21 shaping, RP 2110-24 SD.
        ("video-segmented", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; segmented")),
        ("video-interlace-rate", with(VIDEO, "exactframerate=50", "exactframerate=50; interlace")),
        ("video-range-bt2100", with(VIDEO, "colorimetry=BT709", "colorimetry=BT2100; RANGE=FULLPROTECT")),
        ("video-key", with(VIDEO, "colorimetry=BT709", "colorimetry=ALPHA")),
        ("video-depth-sampling", with(with(VIDEO, "YCbCr-4:2:2", "YCbCr-4:2:0"), "depth=10", "depth=16")),
        ("video-bpm-maxudp", with(VIDEO, "PM=2110GPM", "PM=2110BPM; MAXUDP=8960")),
        ("video-rfc4175", RFC4175.to_string()),
        ("video-sd-width", sd("width=704; height=486", None)),
        ("video-sd-height", sd("width=720; height=487", Some("10:11"))),
        ("video-sd-par", sd("width=720; height=486", Some("1:1"))),
        ("video-sd-sampling", with(sd("width=720; height=486", Some("10:11")), "YCbCr-4:2:2", "YCbCr-4:4:4")),
        ("tp", with(VIDEO, "TP=2110TPN", "TP=2110TPX")),
        ("tp-wide", with(VIDEO, "TP=2110TPN", "TP=2110TPW")),
        ("shaping-param", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=0")),
        ("troff-nondefault", with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=500")),
        // ST 2110-22.
        ("cbr-bandwidth", with(JPEG_XS, "b=AS:116000\n", "")),
        ("jxsv-tr08", with(JPEG_XS, "packetmode=0", "packetmode=1")),
        ("jxsv-profile", with(JPEG_XS, "level=2k-1", "level=3k-1")),
        ("jxsv-bpp", with(JPEG_XS, "b=AS:116000", "b=AS:400000")),
        ("jxsv-sublevel", with(JPEG_XS, "Sublev3bpp", "Sublev4bpp")),
        ("jxsv-level-lowest", with(with(JPEG_XS, "width=1920", "width=1280"), "height=1080", "height=720")),
        ("jxsv-level", with(JPEG_XS, "width=1920; height=1080", "width=3840; height=2160")),
        // ST 2110-30 and -31.
        ("audio-rate", with(AUDIO, "L24/48000/8", "L24/32000/8")),
        ("audio-ptime-missing", with(AUDIO, "a=ptime:1\n", "")),
        ("audio-ptime", with(AUDIO, "a=ptime:1", "a=ptime:fast")),
        ("audio-level", with(AUDIO, "a=ptime:1", "a=ptime:0.25")),
        ("audio-packet-size", with(with(AUDIO, "L24/48000/8", "L24/48000/16"), "(51,ST)", "(51,51,ST,ST)")),
        ("audio-channel-order", with(AUDIO, "(51,ST)", "(51)")),
        ("maxudp-standard-only", with(AUDIO, "TSMODE=SAMP", "TSMODE=SAMP; MAXUDP=8960")),
        ("aes3-channels", with(AES3, "AM824/48000/8", "AM824/48000/7")),
        ("aes3-ptime", with(AES3, "a=ptime:0.12", "a=ptime:0.125")),
        // ST 2110-40, -41 and -43.
        ("anc-tm", with(ANC, "TM=CTM", "TM=FAST")),
        ("anc-param", with(ANC, "DID_SDID={0x61,0x01}", "DID_SDID={61,01}")),
        ("anc-audio-edh", with(ANC, "DID_SDID={0x60,0x60}", "DID_SDID={0xE7,0x00}")),
        ("fmx-dit", with(FMX, "DIT=100", "DIT=300000")),
        ("fmx-dit-syntax", with(FMX, "DIT=100", "DIT=0x100")),
        ("fmx-mga-clock", with(FMX, "ST2110-41/48000", "ST2110-41/90000")),
        ("media-type", with(ANC, "m=video 5008", "m=audio 5008")),
        // Anything else.
        ("essence-unknown", with(AUDIO, "L24/48000/8", "opus/48000/8")),
    ]
}

/// The video fixture as 525-line interlaced SD with the given size and PAR.
fn sd(size: &str, par: Option<&str>) -> String {
    let par = par.map(|p| format!("; PAR={p}")).unwrap_or_default();
    with(
        VIDEO,
        "width=1920; height=1080; exactframerate=50",
        &format!("{size}; exactframerate=30000/1001; interlace{par}"),
    )
}

#[test]
fn every_case_raises_its_rule() {
    for (rule, text) in cases() {
        let found = ids(&text);
        assert!(found.contains(rule), "expected {rule}, found {found:?} in:\n{text}");
    }
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

#[test]
fn diagnostics_carry_the_rule_severity_and_a_line() {
    for (_, text) in cases() {
        for d in lint(&text).diagnostics {
            let rule = rules::find(d.rule).expect("catalogued rule");
            assert_eq!(d.severity, rule.severity, "{}", d.rule);
            assert!(!d.message.is_empty() && !d.reference.is_empty(), "{}", d.rule);
            if d.rule != "sdp-required-line" {
                assert!(d.line.is_some(), "{} has no line: {}", d.rule, d.message);
            }
        }
    }
}

#[test]
fn clean_fixtures_are_clean() {
    for (name, text) in
        [("video", VIDEO), ("audio", AUDIO), ("anc", ANC), ("jpeg-xs", JPEG_XS), ("fmx", FMX), ("ttml", TTML)]
    {
        assert_eq!(lint(text).diagnostics, [], "{name}");
    }
    assert_eq!(ids(AES3), BTreeSet::from(["tsmode-absent"]));
}

#[test]
fn crlf_and_a_byte_order_mark_are_accepted() {
    let text = format!("\u{feff}{}", VIDEO.replace('\n', "\r\n"));
    assert_eq!(lint(&text).diagnostics, []);
}

#[test]
fn aes67_stream_with_a_random_offset() {
    let report = lint(include_str!("fixtures/aes67-offset.sdp"));
    let found: Vec<(&str, Option<usize>)> = report.diagnostics.iter().map(|d| (d.rule, d.line)).collect();
    assert_eq!(found, [("source-filter-missing", Some(7)), ("tsmode-absent", Some(7)), ("mediaclk-offset", Some(13))]);
    assert_eq!(report.count(Severity::Error), 1);
}

#[test]
fn rfc4175_description() {
    let expected = [
        "mediaclk-missing",
        "param-missing",
        "param-value",
        "sdp-multicast-ttl",
        "source-filter-missing",
        "tp",
        "ts-refclk-missing",
        "tsmode-absent",
        "video-rfc4175",
    ];
    assert_eq!(ids(RFC4175), BTreeSet::from(expected));
}

#[test]
fn summaries() {
    let summary = |text: &str| lint(text).streams.iter().map(|s| s.summary.clone()).collect::<Vec<_>>();
    assert_eq!(
        summary(VIDEO)[0],
        "1920x1080 progressive, 50 fps, YCbCr-4:2:2 10-bit, BT709 SDR, 2110GPM, 2110TPN, 2.07 Gb/s"
    );
    assert_eq!(summary(AUDIO), ["L24 48 kHz, 8 channels (51,ST), 1 ms, level A, 9.22 Mb/s"]);
    assert_eq!(summary(AES3), ["AM824 48 kHz, 8 subframes (4 AES3 pairs), 0.12 ms, level B, 12.29 Mb/s"]);
    assert_eq!(summary(ANC), ["ancillary data (CEA-708 61/01, timecode 60/60), 50 fps, CTM"]);
    assert_eq!(summary(JPEG_XS), ["jxsv 1920x1080 progressive, 59.94 fps, 2110TPN, 116.00 Mb/s (b=AS)"]);
    assert_eq!(summary(FMX), ["fast metadata, DIT 100 (ST 2127-2 audio metadata)"]);
    assert_eq!(summary(TTML), ["TTML timed text (im3t)"]);
}

#[test]
fn stream_model() {
    let report = lint(VIDEO);
    let stream = &report.streams[1];
    assert_eq!(stream.mid.as_deref(), Some("secondary"));
    assert_eq!(stream.destination.as_deref(), Some("239.20.10.1"));
    assert_eq!(stream.port, Some(5004));
    assert_eq!(stream.source.as_deref(), Some("192.168.20.21"));
    assert_eq!((stream.payload_type, stream.clock_rate), (Some(96), Some(90_000)));
    assert_eq!(stream.payload_bitrate, Some(2_073_600_000.0));
    let (grandmaster, domain) = stream.reference_clock.as_ref().and_then(|c| c.grandmaster()).unwrap();
    assert_eq!((grandmaster.to_string().as_str(), domain), ("08-00-11-FF-FE-21-E1-B0", Some(127)));
    assert_eq!(stream.media_clock, Some(st2110_sdp::MediaClock::Direct { offset: Some(0) }));
    assert_eq!(lint(AUDIO).streams[0].channels, Some(8));
}

#[test]
fn valid_variations_raise_nothing() {
    let valid = [
        // 1080i59.94: the frame rate and the frame height.
        with(VIDEO, "exactframerate=50", "exactframerate=30000/1001; interlace"),
        // 1080PsF25.
        with(VIDEO, "exactframerate=50", "exactframerate=25; interlace; segmented"),
        // The default read offset for 1080p50 is 764.4 µs.
        with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=764"),
        // A key signal, which needs the 2022 edition.
        with(
            with(with(VIDEO, "colorimetry=BT709", "colorimetry=ALPHA"), "YCbCr-4:2:2", "KEY"),
            "2110-20:2017",
            "2110-20:2022",
        ),
        // Separators without spaces, and parameters in any order.
        with(VIDEO, "sampling=YCbCr-4:2:2; width=1920; height=1080", "height=1080;width=1920;sampling=YCbCr-4:2:2"),
        // The legs share a destination but come from different sources.
        with(VIDEO, "239.20.10.1", "239.10.10.1"),
        // Traceable time needs no grandmaster or domain.
        with(VIDEO, "08-00-11-FF-FE-21-E1-B0:127", "traceable"),
        // The default read offset for 1080i59.94 is 652.5 µs.
        with(VIDEO, "exactframerate=50", "exactframerate=30000/1001; interlace; TROFF=652"),
        // 525-line video at the ST 2110-21:2017 default, 20/525 of a frame: 1271.1 µs.
        with(sd("width=720; height=486", Some("10:11")), "TSMODE=SAMP", "TSMODE=SAMP; TROFF=1271"),
        // Phases of a high frame rate camera, each with the same format.
        with(VIDEO, "a=group:DUP", "a=group:PHASED"),
        // JPEG XS at a TR-08 profile, level and sublevel, in lower case.
        with(JPEG_XS, "level=2k-1", "level=2K-1"),
        // TR-08 Appendix A: 720p59.94 at level 1k-1, Sublev3bpp.
        with(with(with(JPEG_XS, "width=1920", "width=1280"), "height=1080", "height=720"), "level=2k-1", "level=1k-1"),
        // 1920x1200p60 is over 2k-1's pixel rate, so 4k-2 is the lowest TR-08 level.
        with(with(JPEG_XS, "height=1080; exactframerate=60000/1001", "height=1200; exactframerate=60"), "2k-1", "4k-2"),
        // 2160p59.94 at 4k-2 and 2 bits a pixel; the sublevel in lower case.
        with(
            with(with(JPEG_XS, "width=1920; height=1080", "width=3840; height=2160"), "2k-1", "4k-2"),
            "b=AS:116000",
            "b=AS:1000000",
        )
        .replace("Sublev3bpp", "sublev3bpp"),
        // 1080i59.94 counts a frame's pixels at the frame rate.
        with(JPEG_XS, "exactframerate=60000/1001", "exactframerate=30000/1001; interlace"),
        // Sublev4bpp above 3 bits a pixel.
        with(with(JPEG_XS, "b=AS:116000", "b=AS:400000"), "Sublev3bpp", "Sublev4bpp"),
        // 525-line SD as RP 2110-24 carries it.
        sd("width=720; height=486", Some("10:11")),
        // Level C audio: 16 channels in 125 µs packets.
        with(with(AUDIO, "a=ptime:1", "a=ptime:0.125"), "L24/48000/8", "L24/48000/16")
            .replace("(51,ST)", "(51,51,ST,ST)"),
        // Level A needs no channel-order.
        with(AUDIO, "channel-order=SMPTE2110.(51,ST); ", ""),
        // ANC without TM signals the 2018 edition.
        with(ANC, "TM=CTM;SSN=ST2110-40:2023", "SSN=ST2110-40:2018"),
        // The IANA spelling of the FMX edition, and a list of types.
        with(FMX, "SSN=ST2110-41:2024; DIT=100", "SSN=SMPTE2110-41:2024; DIT=100,2000A1,3FF000"),
    ];
    for text in valid {
        assert_eq!(lint(&text).diagnostics, [], "in:\n{text}");
    }
}

#[test]
fn aes3_levels_at_44_1_and_96_khz() {
    let aes3 = |rate: &str, ptime: &str, subframes: u16| {
        let pairs = vec!["AES3"; usize::from(subframes / 2)].join(",");
        let text = with(AES3, "AM824/48000/8", &format!("AM824/{rate}/{subframes}"));
        let text = with(text, "(AES3,AES3,AES3,AES3)", &format!("({pairs})"));
        with(text, "a=ptime:0.12", &format!("a=ptime:{ptime}"))
    };
    let summary = |text: &str| lint(text).streams[0].summary.clone();
    assert!(summary(&aes3("96000", "1", 2)).contains("level AX"), "{}", summary(&aes3("96000", "1", 2)));
    assert!(summary(&aes3("44100", "0.14", 60)).contains("level CX"));
    assert!(summary(&aes3("96000", "0.08", 40)).contains("level DX"));
    assert_eq!(ids(&aes3("96000", "0.12", 30)), BTreeSet::from(["tsmode-absent"]));
    // 96 kHz at 1 ms carries 2 subframes at most.
    let found = lint(&aes3("96000", "1", 4));
    let level = found.diagnostics.iter().find(|d| d.rule == "audio-level").expect("audio-level");
    assert!(level.message.starts_with("96 kHz with 1 ms packets and 4 subframes fits no ST 2110-31 level: AX is 1 ms"));
}

#[test]
fn data_streams_say_their_media_type() {
    let found = |text: &str| lint(text).diagnostics.into_iter().filter(|d| d.rule == "media-type").count();
    assert_eq!(found(&with(FMX, "m=application", "m=video")), 1);
    assert_eq!(found(&with(TTML, "m=application", "m=text")), 1);
    assert_eq!(found(&with(ANC, "m=video", "m=application")), 1);
    assert_eq!(found(FMX) + found(TTML) + found(ANC), 0);
}

#[test]
fn pcm_audio_and_anc_keep_to_the_standard_udp_limit() {
    // 16 channels of L24 in 1 ms packets is 2304 bytes: too big even when MAXUDP says 8960.
    let audio = with(
        with(with(AUDIO, "L24/48000/8", "L24/48000/16"), "(51,ST)", "(51,51,ST,ST)"),
        "TSMODE=SAMP",
        "TSMODE=SAMP; MAXUDP=8960",
    );
    let found = ids(&audio);
    assert!(found.contains("audio-packet-size") && found.contains("maxudp-standard-only"), "{found:?}");
    let anc = with(ANC, "TSMODE=SAMP", "TSMODE=SAMP;MAXUDP=8960");
    assert!(ids(&anc).contains("maxudp-standard-only"));
    // ST 2110-31 may use the extended limit.
    let aes3 = AES3.lines().map(|l| if l.starts_with("a=fmtp") { format!("{l}; MAXUDP=8960") } else { l.to_string() });
    let aes3 = aes3.collect::<Vec<_>>().join("\n");
    assert!(!ids(&aes3).contains("maxudp-standard-only"));
}

#[test]
fn messages_suggest_the_fix() {
    let message = |text: &str, rule: &str| {
        let report = lint(text);
        report.diagnostics.iter().find(|d| d.rule == rule).map(|d| d.message.clone()).unwrap()
    };
    let decimal = with(VIDEO, "exactframerate=50", "exactframerate=59.94");
    assert!(message(&decimal, "frame-rate").ends_with("write 60000/1001"));
    let field_rate = with(VIDEO, "exactframerate=50", "exactframerate=60000/1001; interlace");
    assert!(message(&field_rate, "video-interlace-rate").ends_with("write 30000/1001"));
    let alpha = with(VIDEO, "colorimetry=BT709", "colorimetry=ALPHA");
    assert!(message(&alpha, "ssn").contains("SSN=ST2110-20:2022"));
    let offset = with(VIDEO, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=500");
    assert!(message(&offset, "troff-nondefault").contains("default of 764 µs"));
    let interlaced = with(VIDEO, "exactframerate=50", "exactframerate=25; interlace; TROFF=500");
    assert!(message(&interlaced, "troff-nondefault").contains("default of 782 µs for 1080-line interlaced video"));
    // ST 2110-21:2022 misprints the 525- and 625-line defaults; the 2017 ones stand.
    let pal = with(VIDEO, "exactframerate=50", "exactframerate=25; interlace; TROFF=500");
    let pal = with(with(&pal, "width=1920", "width=720"), "height=1080", "height=576");
    assert!(message(&pal, "troff-nondefault").contains("default of 1664 µs for 576-line interlaced video"), "{pal}");
    // A 2SI part that writes out the default read offset reads from the same offset as one
    // that leaves it out.
    let split = with(VIDEO, "a=group:DUP", "a=group:MULTI-2SI");
    assert!(!ids(&with_first(&split, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=764")).contains("multistream-troff"));
    let troff = with_first(&split, "TSMODE=SAMP", "TSMODE=SAMP; TROFF=500");
    assert_eq!(
        message(&troff, "multistream-troff"),
        "secondary has the default TROFF and primary has TROFF=500; the parts of a MULTI-2SI picture are read from one offset"
    );
}

#[test]
fn jpeg_xs_levels_by_the_published_tables() {
    let message = |text: &str, rule: &str| {
        let report = lint(text);
        report.diagnostics.iter().find(|d| d.rule == rule).map(|d| d.message.clone()).unwrap()
    };
    let uhd = with(JPEG_XS, "width=1920; height=1080", "width=3840; height=2160");
    assert_eq!(
        message(&uhd, "jxsv-level"),
        "level=2k-1 does not fit the picture, by the published level tables: width=3840 is over its 2048 pixels a row; \
         3840x2160 is 8294400 pixels a picture, over its 4194304; 3840x2160 at 59.94 frames a second is 497.2 million \
         pixels a second, over its 133.7 million"
    );
    assert_eq!(rules::find("jxsv-level").unwrap().severity, Severity::Warning);
    // Only the pixel rate: 1920x1200p60 is 138.2 million pixels a second.
    let wuxga = with(JPEG_XS, "height=1080; exactframerate=60000/1001", "height=1200; exactframerate=60");
    assert!(message(&wuxga, "jxsv-level").ends_with("138.2 million pixels a second, over its 133.7 million"));
    // Level names in any case, Bayer names and Unrestricted are known; others are not.
    let unknown = with(JPEG_XS, "level=2k-1", "level=3k-1");
    assert_eq!(
        message(&unknown, "jxsv-level"),
        "level=3k-1 is not a level the JPEG XS tables name, such as 2k-1 or 4k-2"
    );
    for level in ["level=2K-1", "level=Bayer4k-1", "level=unrestricted"] {
        assert!(!ids(&with(JPEG_XS, "level=2k-1", level)).contains("jxsv-level"), "{level}");
    }
    let sublevel = with(JPEG_XS, "Sublev3bpp", "Sublev5bpp");
    assert!(message(&sublevel, "jxsv-level").starts_with("sublevel=Sublev5bpp is not a sublevel"));
    assert!(!ids(&with(JPEG_XS, "Sublev3bpp", "Sublev12bpp")).contains("jxsv-level"));
    // TR-08's lowest level: 720p59.94 fits 1k-1.
    let hd = with(with(JPEG_XS, "width=1920", "width=1280"), "height=1080", "height=720");
    assert_eq!(
        message(&hd, "jxsv-level-lowest"),
        "level=2k-1, but 1280x720 at 59.94 frames a second fits level 1k-1, which is lower: TR-08 asks for the lowest \
         level that fits"
    );
    // A level outside TR-08's is left to jxsv-profile.
    assert!(!ids(&with(hd, "level=2k-1", "level=4k-1")).contains("jxsv-level-lowest"));
    let four = with(JPEG_XS, "Sublev3bpp", "Sublev4bpp");
    assert_eq!(
        message(&four, "jxsv-sublevel"),
        "sublevel=Sublev4bpp, but b=AS:116000 is 0.9 bits a pixel: TR-08 signals Sublev3bpp up to 3 (Sublev2bpp in \
         capability sets E and F), and Sublev4bpp only above 3"
    );
}

#[test]
fn docs_list_every_rule() {
    let docs = include_str!("../../../docs/rules.md");
    assert!(
        docs.contains(&rules::markdown_table(rules::ALL)),
        "docs/rules.md is stale: run `st2110 rules --format markdown > docs/rules.md`"
    );
}
