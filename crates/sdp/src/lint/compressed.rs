//! ST 2110-22 constant bit-rate compressed video, such as JPEG XS (RFC 9134).

use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rules;
use crate::sdp::parse_bandwidth;
use crate::stream::Media;

use super::params::{self, Names};

/// Where ST 2110-22 lists its SDP requirements.
const PARAMS: &str = "ST 2110-22:2022 §7";

const NAMES: Names<'static> = Names {
    known: &[
        "width",
        "height",
        "exactframerate",
        "SSN",
        // RFC 9134 (JPEG XS).
        "packetmode",
        "transmode",
        "profile",
        "level",
        "sublevel",
        "depth",
        "sampling",
        "colorimetry",
        "TCS",
        "RANGE",
        "interlace",
        "segmented",
    ],
    strict: false,
    repeatable: &[],
};

pub(super) fn check(m: &Media<'_>, d: &mut Diagnostics) {
    super::clock_rate(m, d, 90_000, "ST 2110-22:2022 §5");
    bandwidth(m, d);
    let Some((line, fmtp)) = m.format() else {
        d.report(
            &rules::PARAM_MISSING,
            m.index,
            m.line,
            "no a=fmtp line, so width, height, TP and the frame rate are not given",
        )
        .cite(PARAMS);
        return;
    };
    params::check(m, line, fmtp, &NAMES, d);
    for name in ["width", "height"] {
        params::require(m, line, fmtp, name, PARAMS, d);
        params::number(m, line, fmtp, name, 1..=65535, PARAMS, d);
    }
    super::sender_type(m, d, line, fmtp, PARAMS);
    if fmtp.has("exactframerate") {
        super::exact_frame_rate(m, d, line, fmtp, PARAMS);
    } else if m.section.attribute("framerate").is_none() {
        d.report(&rules::PARAM_MISSING, m.index, line, "no frame rate: give exactframerate, or an a=framerate line")
            .cite(PARAMS);
    }
    if let Some(param) = fmtp.get("SSN") {
        let value = param.value.as_deref().unwrap_or("");
        if !matches!(value, "ST2110-22:2019" | "ST2110-22:2022") {
            d.report(&rules::SSN, m.index, line, format!("SSN={value} is not ST2110-22:2019 or ST2110-22:2022"))
                .cite(PARAMS);
        }
    }
    if m.rtpmap.as_ref().is_some_and(|(_, map)| map.encoding.eq_ignore_ascii_case("jxsv")) {
        jpeg_xs(m, line, fmtp, d);
    }
}

/// The `b=AS` bandwidth in kbit/s, from the media section.
fn average_bandwidth(m: &Media<'_>) -> Option<u64> {
    m.section
        .fields_of('b')
        .filter_map(|field| parse_bandwidth(&field.value).ok())
        .find_map(|(kind, kbps)| (kind == "AS").then_some(kbps))
}

fn bandwidth(m: &Media<'_>, d: &mut Diagnostics) {
    if average_bandwidth(m).is_some() {
        return;
    }
    let at_session =
        m.session.fields_of('b').any(|field| parse_bandwidth(&field.value).is_ok_and(|(kind, _)| kind == "AS"));
    let message = if at_session {
        "b=AS is only at session level; ST 2110-22 puts each stream's bit rate in its media section"
    } else {
        "no b=AS:<kbit/s> line: ST 2110-22 senders state their constant bit rate, counting whole IP packets"
    };
    d.report(&rules::CBR_BANDWIDTH, m.index, m.line, message);
}

fn jpeg_xs(m: &Media<'_>, line: usize, fmtp: &Fmtp, d: &mut Diagnostics) {
    match fmtp.get("packetmode").map(|p| p.value.as_deref().unwrap_or("")) {
        None => {
            d.report(
                &rules::PARAM_MISSING,
                m.index,
                line,
                "packetmode is required for JPEG XS: 0 for codestream mode, 1 for slice mode",
            )
            .cite("RFC 9134");
        }
        Some("0") => {}
        Some("1") => {
            d.report(
                &rules::JXSV_TR08,
                m.index,
                line,
                "packetmode=1 (slice mode): JPEG XS equipment built to VSF TR-08 expects codestream mode, packetmode=0",
            );
        }
        Some(other) => {
            d.report(
                &rules::PARAM_VALUE,
                m.index,
                line,
                format!("packetmode={other} is not 0 (codestream mode) or 1 (slice mode)"),
            )
            .cite("RFC 9134");
        }
    }
    if let Some(value) = fmtp.value("transmode")
        && !matches!(value, "0" | "1")
    {
        d.report(&rules::PARAM_VALUE, m.index, line, format!("transmode={value} is not 0 or 1")).cite("RFC 9134");
    }
    tr08_profile(m, line, fmtp, d);
}

/// The profiles, levels, sublevels and depths that VSF TR-08:2026 §8.1.1 allows, as
/// RFC 9134 writes them: without spaces.
fn tr08_profile(m: &Media<'_>, line: usize, fmtp: &Fmtp, d: &mut Diagnostics) {
    let mut report = |message: String| {
        d.report(&rules::JXSV_PROFILE, m.index, line, message);
    };
    let is = |value: &str, names: &[&str]| names.iter().any(|name| name.eq_ignore_ascii_case(value));
    let four_two_zero = fmtp.value("sampling").is_some_and(|s| s.ends_with("4:2:0"));
    if let Some(profile) = fmtp.value("profile") {
        if is(profile, &["High420.12"]) && !four_two_zero {
            report(format!("profile={profile} carries 4:2:0 only; other sampling uses High444.12 or TDC444.12"));
        } else if !is(profile, &["High444.12", "TDC444.12", "High420.12"]) {
            report(format!("profile={profile}: TR-08 uses High444.12 or TDC444.12, or High420.12 for 4:2:0"));
        }
    }
    if let Some(level) = fmtp.value("level")
        && !is(level, &["1k-1", "2k-1", "4k-2", "8k-2"])
    {
        report(format!("level={level}: TR-08 uses 1k-1, 2k-1, 4k-2 or 8k-2"));
    }
    if let Some(sublevel) = fmtp.value("sublevel")
        && !is(sublevel, &["Sublev2bpp", "Sublev3bpp", "Sublev4bpp"])
    {
        report(format!(
            "sublevel={sublevel}: TR-08 uses Sublev2bpp, Sublev3bpp or Sublev4bpp, for at most 4 bits a pixel"
        ));
    }
    if let Some(depth) = fmtp.value("depth")
        && !matches!(depth, "8" | "10" | "12")
    {
        report(format!("depth={depth}: TR-08 codes 8, 10 or 12 bits a sample"));
    }
}

pub(super) fn describe(m: &Media<'_>) -> (String, Option<f64>) {
    let encoding = m.rtpmap.as_ref().map_or("compressed video", |(_, map)| map.encoding.as_str());
    let mut parts = Vec::new();
    match m.format() {
        Some((_, fmtp)) => {
            let scan = super::scan(fmtp);
            match (fmtp.value("width"), fmtp.value("height")) {
                (Some(w), Some(h)) => parts.push(format!("{encoding} {w}x{h} {scan}")),
                _ => parts.push(format!("{encoding} {scan}")),
            }
            if let Some(rate) = fmtp.value("exactframerate").and_then(super::read_frame_rate) {
                parts.push(format!("{} fps", super::fps(rate)));
            }
            if let Some(tp) = fmtp.value("TP") {
                parts.push(tp.to_string());
            }
        }
        None => parts.push(encoding.to_string()),
    }
    if let Some(kbps) = average_bandwidth(m) {
        parts.push(format!("{} (b=AS)", super::bitrate(kbps as f64 * 1000.0)));
    }
    (parts.join(", "), None)
}
