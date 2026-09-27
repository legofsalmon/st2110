//! The rule catalogue.
//!
//! Every diagnostic comes from one of these rules. A diagnostic may cite a more
//! specific clause than the rule's general reference.

use crate::diag::{Rule, Severity};

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
    // Session description structure (RFC 8866).
    SDP_SYNTAX = "sdp-syntax", Error, "RFC 8866 §5",
        "Every line is `<type>=<value>`: one lowercase letter, then `=`, with no spaces around it.";
    SDP_BLANK_LINE = "sdp-blank-line", Warning, "RFC 8866 §5",
        "Blank lines are not part of SDP, and strict parsers reject them.";
    SDP_UNKNOWN_TYPE = "sdp-unknown-type", Error, "RFC 8866 §5",
        "A line type RFC 8866 does not define; a parser may reject the whole description.";
    SDP_ORDER = "sdp-order", Warning, "RFC 8866 §5",
        "Lines follow RFC 8866's order (v o s i u e p c b t r z k a, then m i c b k a per media section); strict parsers reject others.";
    SDP_VERSION = "sdp-version", Error, "RFC 8866 §5.1",
        "The description starts with `v=0`.";
    SDP_REQUIRED_LINE = "sdp-required-line", Error, "RFC 8866 §5",
        "The session level has `o=`, `s=` and `t=` lines.";
    SDP_DUPLICATE_LINE = "sdp-duplicate-line", Error, "RFC 8866 §5",
        "A line type that may appear only once in its section appears again.";
    SDP_ORIGIN = "sdp-origin", Error, "RFC 8866 §5.2",
        "`o=` has six fields, with a numeric session id and version.";
    SDP_SESSION_NAME = "sdp-session-name", Error, "RFC 8866 §5.3",
        "`s=` is not empty; use `s=-` when there is no name.";
    SDP_TIMING = "sdp-timing", Error, "RFC 8866 §5.9",
        "`t=` holds a start and a stop time, such as `t=0 0`.";
    SDP_MEDIA_LINE = "sdp-media-line", Error, "RFC 8866 §5.14",
        "`m=` has a media type, a port, a protocol and at least one format.";
    SDP_CONNECTION = "sdp-connection", Error, "RFC 8866 §5.7",
        "Each media section has a valid connection address, in its own `c=` line or at session level.";
    SDP_MULTICAST_TTL = "sdp-multicast-ttl", Warning, "RFC 8866 §5.7",
        "IPv4 multicast addresses carry a TTL (`/32`); unicast addresses do not.";
    SDP_BANDWIDTH = "sdp-bandwidth", Error, "RFC 8866 §5.8",
        "`b=` is `<type>:<kbit/s>`.";
    SDP_DUPLICATE_ATTRIBUTE = "sdp-duplicate-attribute", Error, "RFC 8866 §6",
        "A payload type has two `a=rtpmap` or two `a=fmtp` lines, or a section has two `a=mid` lines.";
    MEDIA_DISABLED = "media-disabled", Warning, "RFC 8866 §5.14",
        "Port 0 disables a media section.";

    // RTP.
    RTP_PROFILE = "rtp-profile", Warning, "RFC 3551",
        "ST 2110 streams use the `RTP/AVP` profile.";
    RTP_PAYLOAD_TYPE = "rtp-payload-type", Error, "ST 2110-10:2022",
        "Payload types are dynamic: 96 to 127.";
    RTP_SINGLE_FORMAT = "rtp-single-format", Warning, "RFC 8866 §5.14",
        "A stream lists one payload type; only the first is checked.";
    RTP_CLOCK_RATE = "rtp-clock-rate", Error, "ST 2110-20 §6.1 · -22 §5 · -40 · -43 §4.2 · ST 2022-8",
        "The RTP clock runs at the rate the essence standard fixes: 90 kHz for video, ANC and timed text, 27 MHz for ST 2022-6.";
    RTPMAP_MISSING = "rtpmap-missing", Error, "RFC 8866 §6.6",
        "A dynamic payload type is described by an `a=rtpmap` line.";
    RTPMAP_SYNTAX = "rtpmap-syntax", Error, "RFC 8866 §6.6",
        "`a=rtpmap` is `<payload type> <encoding>/<clock rate>[/<channels>]`.";
    FORMAT_UNLISTED = "format-unlisted", Warning, "RFC 8866 §6.6",
        "An `a=rtpmap` or `a=fmtp` line names a payload type the `m=` line does not list.";

    // Format parameters.
    FMTP_SYNTAX = "fmtp-syntax", Error, "RFC 8866 §6.15",
        "Format parameters are `name=value` or `name`, separated by `;`.";
    FMTP_DUPLICATE_PARAM = "fmtp-duplicate-param", Error, "RFC 8866 §6.15",
        "A parameter appears twice; only `DID_SDID` may repeat.";
    FMTP_PARAM_CASE = "fmtp-param-case", Warning, "RFC 2045 §5.1",
        "A parameter name differs in case from the standard's spelling; receivers that compare names exactly will miss it.";
    FMTP_QUOTED_VALUE = "fmtp-quoted-value", Warning, "ST 2110-20:2022 §7",
        "A quoted value; ST 2110 SDPs use bare values, and some receivers keep the quotes.";
    FMTP_UNKNOWN_PARAM = "fmtp-unknown-param", Warning, "ST 2110-20:2022 §7",
        "A video parameter that ST 2110-20, -21 and -10 do not define; receivers may ignore or reject it.";
    PARAM_MISSING = "param-missing", Error, "ST 2110-20 §7.2 · -22 §7 · -40 §7 · -41 · -43",
        "A parameter the essence standard requires is missing.";
    PARAM_VALUE = "param-value", Error, "ST 2110-20 §7 · -22 §7",
        "A parameter has a value the standard does not define.";
    FRAME_RATE = "frame-rate", Error, "ST 2110-20:2022 §7.2",
        "`exactframerate` is a whole number or a ratio such as `60000/1001`, never a decimal.";
    FRAME_RATE_FORM = "frame-rate-form", Warning, "ST 2110-20:2022 §7.2",
        "Whole-number frame rates are written as one number, and ratios in lowest terms.";
    SSN = "ssn", Error, "ST 2110-20 §7 · -22 §7 · -40 §7 · -41",
        "`SSN` names the edition that matches what the stream uses.";
    SSN_TYPO = "ssn-typo", Warning, "ST 2110-40:2023 advisory note",
        "`ST2110-40:2021` is a misprint of `ST2110-40:2023`.";

    // ST 2110-10: clocks, addressing and shared parameters.
    TS_REFCLK_MISSING = "ts-refclk-missing", Error, "ST 2110-10:2022 §8.2",
        "Each stream names its reference clock with `a=ts-refclk`.";
    TS_REFCLK_SYNTAX = "ts-refclk-syntax", Error, "RFC 7273 §4",
        "The `a=ts-refclk` value is malformed.";
    TS_REFCLK_NOT_PTP = "ts-refclk-not-ptp", Error, "ST 2110-10:2022 §8.2",
        "The reference clock is PTP (`ptp=IEEE1588-2008:...`), or `localmac` when there is no PTP.";
    TS_REFCLK_PTP_VERSION = "ts-refclk-ptp-version", Warning, "ST 2110-10:2022 §8.2",
        "ST 2110-10:2022 and NMOS IS-04 name the PTP version `IEEE1588-2008`.";
    TS_REFCLK_DOMAIN = "ts-refclk-domain", Warning, "ST 2059-2:2021 §6.5",
        "The PTP domain is given, within ST 2059-2's range of 0 to 127.";
    TS_REFCLK_LOCALMAC = "ts-refclk-localmac", Warning, "ST 2110-10:2022 §8.2",
        "`localmac`: the sender is not locked to PTP, so its timestamps cannot be aligned with other sources.";
    MEDIACLK_MISSING = "mediaclk-missing", Error, "ST 2110-10:2022 §8.3",
        "Each stream declares `a=mediaclk:direct=0`, or `sender`.";
    MEDIACLK_VALUE = "mediaclk-value", Error, "ST 2110-10:2022 §8.3",
        "`a=mediaclk` is `direct=0` or `sender`.";
    MEDIACLK_OFFSET = "mediaclk-offset", Error, "ST 2110-10:2022 §7.3",
        "The RTP clock offset is zero: `a=mediaclk:direct=0`.";
    MEDIACLK_OFFSET_IMPLICIT = "mediaclk-offset-implicit", Warning, "ST 2110-10:2022 §8.3",
        "`direct` without `=0`; ST 2110 writes the zero offset out.";
    MEDIACLK_SENDER = "mediaclk-sender", Warning, "ST 2110-10:2022 §8.3",
        "`mediaclk:sender`: the media clock is not locked to the reference clock.";
    CLOCK_SESSION_LEVEL = "clock-session-level", Warning, "ST 2110-10:2022 §8",
        "`ts-refclk` or `mediaclk` appears only at session level; ST 2110 puts both in each media section.";
    SOURCE_FILTER_MISSING = "source-filter-missing", Warning, "ST 2110-10:2022 §8.4",
        "A multicast stream carries `a=source-filter: incl`, so receivers join source-specific (IGMPv3).";
    SOURCE_FILTER_SYNTAX = "source-filter-syntax", Error, "RFC 4570",
        "`a=source-filter` is `<incl|excl> IN <IP4|IP6|*> <destination> <source>...`.";
    SOURCE_FILTER_MISMATCH = "source-filter-mismatch", Error, "RFC 4570",
        "No source filter names the stream's destination address.";
    MAXUDP = "maxudp", Error, "ST 2110-10:2022",
        "`MAXUDP` is a whole number of octets, at most the 8960-octet extended limit.";
    MAXUDP_EXTENDED = "maxudp-extended", Warning, "ST 2110-10:2022",
        "`MAXUDP` above 1460: receivers are only required to handle the standard limit.";
    TSMODE = "tsmode", Error, "ST 2110-10:2022 §8.7",
        "`TSMODE` is `SAMP`, `PRES` or `NEW`.";
    TSMODE_ABSENT = "tsmode-absent", Info, "ST 2110-10:2022 §8.7",
        "No `TSMODE`: the timestamps count as `NEW` (made at egress), not as sampling instants.";
    TSDELAY = "tsdelay", Error, "ST 2110-10:2022 §8.7",
        "`TSDELAY` is a whole number of microseconds.";

    // Grouping, ST 2022-7 redundancy and RP 2110-23 multi-stream video.
    GROUP_SYNTAX = "group-syntax", Error, "RFC 5888 §5",
        "`a=group:<semantics> <mid>...` sits at session level and names at least one stream.";
    GROUP_MID_MISSING = "group-mid-missing", Error, "RFC 5888 §5",
        "A group names an `a=mid` that no media section declares.";
    MID_DUPLICATE = "mid-duplicate", Error, "RFC 5888 §4",
        "Two media sections share one `a=mid`.";
    DUP_GROUP = "dup-group", Error, "ST 2110-10:2022 §8.5",
        "A `DUP` group joins at least two streams.";
    DUP_MISMATCH = "dup-mismatch", Error, "SMPTE ST 2022-7:2019",
        "Redundant legs carry identical RTP streams: the same media type, payload type, `rtpmap` and `fmtp`.";
    DUP_ADDRESSING = "dup-addressing", Error, "ST 2110-10:2022 §8.5",
        "Redundant legs do not share both their source and their destination address.";
    DUP_REFCLK = "dup-refclk", Warning, "SMPTE ST 2022-7:2019",
        "Redundant legs name different reference clocks, although their timestamps must be identical.";
    MULTISTREAM_DEPRECATED = "multistream-deprecated", Warning, "RP 2110-23:2019 §5.2",
        "`MULTI-SD` (square division) is deprecated for new designs; use `MULTI-2SI`.";
    MULTISTREAM_COUNT = "multistream-count", Warning, "RP 2110-23:2019 §5.2",
        "A `MULTI-2SI` group has 4 streams (2160 lines) or 16 (4320 lines).";
    MULTISTREAM_ADDRESSES = "multistream-addresses", Error, "RP 2110-23:2019 §5",
        "Each stream of a multi-stream group has its own multicast address.";
    FID_ANC = "fid-anc", Error, "ST 2110-40:2023 §7",
        "`FID` grouping is not used with ANC streams.";

    // ST 2110-20 video, ST 2110-21 traffic shaping, RP 2110-24 SD.
    VIDEO_SEGMENTED = "video-segmented", Error, "ST 2110-20:2022 §7",
        "`segmented` (PsF) is only used together with `interlace`.";
    VIDEO_INTERLACE_RATE = "video-interlace-rate", Warning, "ST 2110-20:2022 §7.2",
        "For interlaced video, `exactframerate` is the frame rate and `height` the frame height (1080i59.94 is `30000/1001`, `height=1080`).";
    VIDEO_RANGE_BT2100 = "video-range-bt2100", Error, "ST 2110-20:2022 §7",
        "`RANGE=FULLPROTECT` is not allowed with `colorimetry=BT2100`.";
    VIDEO_KEY = "video-key", Warning, "ST 2110-20:2022 §7",
        "`colorimetry=ALPHA` describes a key signal and goes with `sampling=KEY`.";
    VIDEO_DEPTH_SAMPLING = "video-depth-sampling", Error, "ST 2110-20:2022 §6",
        "ST 2110-20 defines no pixel group for this sampling and depth (4:2:0 stops at 12 bits).";
    VIDEO_BPM_MAXUDP = "video-bpm-maxudp", Error, "ST 2110-20:2022 §6.3",
        "Block packing mode (`2110BPM`) never uses the extended UDP size (`MAXUDP`).";
    VIDEO_RFC4175 = "video-rfc4175", Info, "RFC 4175",
        "Looks like an RFC 4175 description: the same `raw` format numbers rows differently from ST 2110-20.";
    VIDEO_SD_WIDTH = "video-sd-width", Warning, "RP 2110-24:2023 §4.2",
        "SD video is sent 720 samples wide.";
    VIDEO_SD_HEIGHT = "video-sd-height", Warning, "RP 2110-24:2023 §4.3–4.4",
        "In Standard Mode, SD height is 480 to 486 for 525-line video and 576 for 625-line video.";
    VIDEO_SD_PAR = "video-sd-par", Warning, "RP 2110-24:2023 §5",
        "SD signals its pixel aspect ratio: 10:11 or 40:33 for 525 lines, 12:11 or 16:11 for 625 lines.";
    TP = "tp", Error, "ST 2110-21:2022 §8",
        "`TP` names the sender type: `2110TPN`, `2110TPNL` or `2110TPW`.";
    TP_WIDE = "tp-wide", Info, "ST 2110-21:2022 §7.2",
        "A Type W sender: Type N (narrow) receivers are not required to accept it.";
    SHAPING_PARAM = "shaping-param", Error, "ST 2110-21:2022 §8",
        "`TROFF` is a positive whole number of microseconds, and `CMAX` a positive whole number of packets.";
    TROFF_NONDEFAULT = "troff-nondefault", Warning, "ST 2110-21:2022 §7.2",
        "A non-default `TROFF`: Type N receivers are only required to accept the default.";

    // ST 2110-22 compressed video.
    CBR_BANDWIDTH = "cbr-bandwidth", Error, "ST 2110-22:2022 §7",
        "Compressed video carries `b=AS:<kbit/s>` in its media section.";
    JXSV_TR08 = "jxsv-tr08", Warning, "VSF TR-08:2022",
        "JPEG XS in ST 2110-22 uses codestream mode (`packetmode=0`).";

    // ST 2110-30 PCM audio and ST 2110-31 AES3.
    AUDIO_RATE = "audio-rate", Error, "ST 2110-30:2025 §6.1 · ST 2110-31:2022",
        "The sampling rate is 48 kHz, 44.1 kHz or 96 kHz.";
    AUDIO_PTIME_MISSING = "audio-ptime-missing", Warning, "ST 2110-30:2025 §6.2.1",
        "No `a=ptime`, so receivers cannot confirm the packet time.";
    AUDIO_PTIME = "audio-ptime", Error, "RFC 8866 §6.4",
        "`a=ptime` is a packet time in milliseconds.";
    AUDIO_LEVEL = "audio-level", Warning, "ST 2110-30:2025 §7",
        "The sampling rate, packet time and channel count fit an ST 2110-30 conformance level.";
    AUDIO_PACKET_SIZE = "audio-packet-size", Error, "ST 2110-10:2022",
        "Each packet fits the UDP size limit: 1440 bytes of RTP payload under the standard 1460-octet limit.";
    AUDIO_CHANNEL_ORDER = "audio-channel-order", Warning, "ST 2110-30:2025 §6.2.2",
        "`channel-order` is `SMPTE2110.(<groups>)` and describes as many channels as the stream carries.";
    AES3_CHANNELS = "aes3-channels", Error, "ST 2110-31:2022 §6.1",
        "AM824 carries AES3 subframe pairs, so the channel count is even.";
    AES3_PTIME = "aes3-ptime", Error, "ST 2110-31:2022 Table 1",
        "`a=ptime` is present and written as in Table 1: 1, 0.12 or 0.08 ms (1.09, 0.14 or 0.09 ms at 44.1 kHz).";

    // ST 2110-40 ancillary data, ST 2110-41 fast metadata.
    ANC_TM = "anc-tm", Error, "ST 2110-40:2023 §7",
        "`TM` is `CTM` or `LLTM`.";
    ANC_PARAM = "anc-param", Error, "RFC 8331",
        "`DID_SDID` is `{0xNN,0xNN}`, and `VPID_Code` a number from 0 to 255.";
    FMX_DIT = "fmx-dit", Warning, "ST 2110-41:2024",
        "`DIT` lists the stream's data item types, none of them from the reserved range.";
    FMX_DIT_SYNTAX = "fmx-dit-syntax", Error, "ST 2110-41:2024",
        "`DIT` is a comma-separated list of 22-bit uppercase hex values, without `0x` or spaces.";

    // Anything else.
    ESSENCE_UNKNOWN = "essence-unknown", Info, "ST 2110",
        "Not an ST 2110 essence format, so only the ST 2110-10 checks apply.";
}

/// Looks a rule up by its identifier.
pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().copied().find(|rule| rule.id == id)
}

/// The catalogue as a Markdown page, as published in `docs/rules.md`.
pub fn markdown() -> String {
    format!(
        "# Lint rules\n\n\
         Generated by `st2110 rules --format markdown`. Severity: **error** breaks a \"shall\" \
         (or an RFC \"MUST\"), **warning** breaks a \"should\" or is a known interoperability \
         hazard, **info** is a note that needs no action on its own.\n\n{}",
        markdown_table(ALL)
    )
}

/// Rules as a Markdown table.
pub fn markdown_table(rules: &[&Rule]) -> String {
    let mut out = String::from("| Rule | Severity | Reference | Checks that |\n|---|---|---|---|\n");
    for rule in rules {
        // A pipe ends a table cell even inside a code span unless it is escaped.
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            rule.id,
            rule.severity,
            rule.reference,
            rule.summary.replace('|', "\\|")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for rule in ALL {
            assert!(seen.insert(rule.id), "duplicate rule id {}", rule.id);
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
        assert_eq!(find("mediaclk-offset"), Some(&MEDIACLK_OFFSET));
        assert_eq!(find("no-such-rule"), None);
    }
}
