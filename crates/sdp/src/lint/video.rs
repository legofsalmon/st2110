//! ST 2110-20 uncompressed video, with ST 2110-21 traffic shaping and RP 2110-24 SD.

use crate::Rational;
use crate::diag::Diagnostics;
use crate::fmtp::{Fmtp, Param};
use crate::rational::digits;
use crate::rules;
use crate::stream::Media;
use crate::video::{Depth, Sampling, payload_bitrate, pixel_group, tro_default_progressive};

use super::params::{self, Names};

/// Where ST 2110-20 defines its format parameters.
const PARAMS: &str = "ST 2110-20:2022 §7";
/// Where ST 2110-20 lists the parameters every sender signals.
const REQUIRED: &str = "ST 2110-20:2022 §7.2";

const NAMES: Names<'static> = Names {
    known: &[
        "sampling",
        "depth",
        "width",
        "height",
        "exactframerate",
        "colorimetry",
        "PM",
        "SSN",
        "interlace",
        "segmented",
        "TCS",
        "RANGE",
        "PAR",
        // Added by VSF TR-10 (IPMX) to describe the source's own timing.
        "measuredpixclk",
        "htotal",
        "vtotal",
    ],
    strict: true,
    repeatable: &[],
};

const REQUIRED_PARAMS: [&str; 8] =
    ["sampling", "depth", "width", "height", "exactframerate", "colorimetry", "PM", "SSN"];
const COLORIMETRY: [&str; 9] =
    ["BT601", "BT709", "BT2020", "BT2100", "ST2065-1", "ST2065-3", "XYZ", "ALPHA", "UNSPECIFIED"];
const TCS: [&str; 11] = [
    "SDR",
    "PQ",
    "HLG",
    "LINEAR",
    "BT2100LINPQ",
    "BT2100LINHLG",
    "ST2065-1",
    "ST428-1",
    "DENSITY",
    "ST2115LOGS3",
    "UNSPECIFIED",
];
const RANGE: [&str; 3] = ["NARROW", "FULLPROTECT", "FULL"];
const PACKING: [&str; 2] = ["2110GPM", "2110BPM"];

/// The picture format, as far as the parameters could be read.
#[derive(Default)]
struct Picture {
    sampling: Option<Sampling>,
    depth: Option<Depth>,
    width: Option<u32>,
    height: Option<u32>,
    rate: Option<Rational>,
    interlaced: bool,
    segmented: bool,
}

impl Picture {
    /// Reads the format without reporting anything, for the stream summary.
    fn read(fmtp: &Fmtp) -> Self {
        let size = |name| fmtp.value(name).and_then(digits).and_then(|n| u32::try_from(n).ok());
        Self {
            sampling: fmtp.value("sampling").and_then(|s| s.parse().ok()),
            depth: fmtp.value("depth").and_then(|s| s.parse().ok()),
            width: size("width"),
            height: size("height"),
            rate: fmtp.value("exactframerate").and_then(super::read_frame_rate),
            interlaced: fmtp.has("interlace"),
            segmented: fmtp.has("segmented"),
        }
    }

    fn payload_bitrate(&self) -> Option<f64> {
        payload_bitrate(self.sampling?, self.depth?, self.width?, self.height?, self.rate?)
    }
}

pub(super) fn check(m: &Media<'_>, d: &mut Diagnostics) {
    super::clock_rate(m, d, 90_000, "ST 2110-20:2022 §6.1");
    let Some((line, fmtp)) = m.format() else {
        d.report(
            &rules::PARAM_MISSING,
            m.index,
            m.line,
            "no a=fmtp line, so none of the required video parameters is given: sampling, depth, width, height, exactframerate, colorimetry, PM, SSN and TP",
        )
        .cite(REQUIRED);
        return;
    };
    params::check(m, line, fmtp, &NAMES, d);
    if looks_like_rfc4175(fmtp) {
        d.report(
            &rules::VIDEO_RFC4175,
            m.index,
            line,
            "this reads like an RFC 4175 description; ST 2110-20 receivers number rows from the top of the picture rather than by interface line, and expect PM, SSN and exactframerate",
        );
    }
    for name in REQUIRED_PARAMS {
        params::require(m, line, fmtp, name, REQUIRED, d);
    }

    let sampling_names = Sampling::ALL.map(Sampling::as_str);
    let depth_names = Depth::ALL.map(Depth::as_str);
    let picture = Picture {
        sampling: params::one_of(m, line, fmtp, "sampling", &sampling_names, PARAMS, d).and_then(|s| s.parse().ok()),
        depth: params::one_of(m, line, fmtp, "depth", &depth_names, PARAMS, d).and_then(|s| s.parse().ok()),
        width: params::number(m, line, fmtp, "width", 1..=32767, REQUIRED, d),
        height: params::number(m, line, fmtp, "height", 1..=32767, REQUIRED, d),
        rate: super::exact_frame_rate(m, d, line, fmtp, REQUIRED),
        interlaced: flag(m, line, fmtp.get("interlace"), d),
        segmented: flag(m, line, fmtp.get("segmented"), d),
    };
    let colorimetry = colorimetry(m, line, fmtp, d);
    let tcs = params::one_of(m, line, fmtp, "TCS", &TCS, PARAMS, d);
    let range = params::one_of(m, line, fmtp, "RANGE", &RANGE, PARAMS, d);
    let packing = params::one_of(m, line, fmtp, "PM", &PACKING, PARAMS, d);
    if let Some(param) = fmtp.get("PAR") {
        pixel_aspect_ratio(m, line, param, d);
    }
    ssn(m, line, fmtp, colorimetry, tcs, d);

    if picture.segmented && !picture.interlaced {
        d.report(&rules::VIDEO_SEGMENTED, m.index, line, "segmented without interlace; PsF is signalled with both");
    }
    if picture.interlaced {
        interlace(m, line, &picture, d);
    }
    if range == Some("FULLPROTECT") && colorimetry == Some("BT2100") {
        d.report(
            &rules::VIDEO_RANGE_BT2100,
            m.index,
            line,
            "RANGE=FULLPROTECT with colorimetry=BT2100: BT.2100 signals are NARROW or FULL",
        );
    }
    if let Some(sampling) = picture.sampling
        && colorimetry == Some("ALPHA")
        && sampling != Sampling::Key
    {
        d.report(
            &rules::VIDEO_KEY,
            m.index,
            line,
            format!("colorimetry=ALPHA describes a key signal, which is sent as sampling=KEY, not {sampling}"),
        );
    }
    if let (Some(sampling), Some(depth)) = (picture.sampling, picture.depth)
        && pixel_group(sampling, depth).is_none()
    {
        d.report(
            &rules::VIDEO_DEPTH_SAMPLING,
            m.index,
            line,
            format!("{sampling} has no pixel group at depth={depth}; 4:2:0 goes up to 12 bits"),
        );
    }
    if packing == Some("2110BPM")
        && let Some(maxudp) = m.maxudp().filter(|n| *n > 1460)
    {
        d.report(
            &rules::VIDEO_BPM_MAXUDP,
            m.index,
            line,
            format!("PM=2110BPM with MAXUDP={maxudp}: block packing fits its 180-octet blocks within the standard 1460-octet limit"),
        );
    }
    super::sender_type(m, d, line, fmtp, "ST 2110-21:2022 §8");
    read_offset(m, line, fmtp, &picture, d);
    standard_definition(m, line, fmtp, &picture, d);
}

/// RFC 4175 uses the same `raw` encoding name; its descriptions lack the ST 2110-20
/// parameters, or use values and parameters only RFC 4175 has.
fn looks_like_rfc4175(fmtp: &Fmtp) -> bool {
    let no_2110 = !fmtp.has("PM") && !fmtp.has("SSN") && !fmtp.has("exactframerate");
    let rfc_params = ["top-field-first", "chroma-position", "gamma"].iter().any(|p| fmtp.has(p));
    let rfc_values = matches!(fmtp.value("colorimetry"), Some("BT601-5" | "BT709-2" | "SMPTE240M"))
        || matches!(fmtp.value("sampling"), Some("RGBA" | "BGR" | "BGRA" | "YCbCr-4:1:1"));
    no_2110 || rfc_params || rfc_values
}

/// A parameter such as `interlace` that is present or absent and takes no value.
fn flag(m: &Media<'_>, line: usize, param: Option<&Param>, d: &mut Diagnostics) -> bool {
    let Some(param) = param else { return false };
    if let Some(value) = &param.value {
        d.report(
            &rules::PARAM_VALUE,
            m.index,
            line,
            format!("{}={value}: {} takes no value, and its presence alone turns it on", param.name, param.name),
        )
        .cite(PARAMS);
    }
    true
}

fn colorimetry<'f>(m: &Media<'_>, line: usize, fmtp: &'f Fmtp, d: &mut Diagnostics) -> Option<&'f str> {
    let rfc4175 = [("BT601-5", "BT601"), ("BT709-2", "BT709")];
    if let Some(value) = fmtp.value("colorimetry")
        && let Some((_, spelling)) = rfc4175.iter().find(|(old, _)| *old == value)
    {
        d.report(
            &rules::PARAM_VALUE,
            m.index,
            line,
            format!("colorimetry={value} is RFC 4175's spelling; ST 2110-20 writes colorimetry={spelling}"),
        )
        .cite(PARAMS);
        return None;
    }
    params::one_of(m, line, fmtp, "colorimetry", &COLORIMETRY, PARAMS, d)
}

fn pixel_aspect_ratio(m: &Media<'_>, line: usize, param: &Param, d: &mut Diagnostics) {
    let value = param.value.as_deref().unwrap_or("");
    let written = value.split_once(':').and_then(|(w, h)| Some((digits(w)?, digits(h)?)));
    let Some(ratio) = written.and_then(|(w, h)| Rational::new(w, h)) else {
        d.report(&rules::PARAM_VALUE, m.index, line, format!("PAR={value} is not a ratio such as 12:11")).cite(PARAMS);
        return;
    };
    let reduced = (ratio.numerator(), ratio.denominator());
    if written != Some(reduced) {
        d.report(
            &rules::PARAM_VALUE,
            m.index,
            line,
            format!("PAR={value}: write it with the smallest whole numbers, {}:{}", reduced.0, reduced.1),
        )
        .cite(PARAMS);
    }
}

/// ST 2110-20:2022 senders still signal the 2017 edition unless they use one of the
/// two values the 2022 edition added.
fn ssn(m: &Media<'_>, line: usize, fmtp: &Fmtp, colorimetry: Option<&str>, tcs: Option<&str>, d: &mut Diagnostics) {
    let Some(param) = fmtp.get("SSN") else { return };
    let value = param.value.as_deref().unwrap_or("");
    let new_feature = if colorimetry == Some("ALPHA") {
        Some("colorimetry=ALPHA")
    } else if tcs == Some("ST2115LOGS3") {
        Some("TCS=ST2115LOGS3")
    } else {
        None
    };
    let expected = if new_feature.is_some() { "ST2110-20:2022" } else { "ST2110-20:2017" };
    if value == expected {
        return;
    }
    let message = match (value, new_feature) {
        ("ST2110-20:2022", None) => "SSN=ST2110-20:2022 is only for streams that use colorimetry=ALPHA or TCS=ST2115LOGS3; other senders signal SSN=ST2110-20:2017, even under the 2022 edition".to_string(),
        ("ST2110-20:2017", Some(feature)) => {
            format!("{feature} is new in ST 2110-20:2022, so this stream signals SSN=ST2110-20:2022")
        }
        _ => format!("SSN={value}: write SSN={expected}"),
    };
    d.report(&rules::SSN, m.index, line, message).cite(REQUIRED);
}

/// Catches field rates and field heights written where ST 2110-20 wants frame values.
fn interlace(m: &Media<'_>, line: usize, picture: &Picture, d: &mut Diagnostics) {
    if let Some(rate) = picture.rate
        && rate.to_f64() > 30.5
    {
        let hint = (rate.denominator().checked_mul(2))
            .and_then(|den| Rational::new(rate.numerator(), den))
            .map(|frame_rate| format!(", so write {frame_rate}"))
            .unwrap_or_default();
        d.report(
            &rules::VIDEO_INTERLACE_RATE,
            m.index,
            line,
            format!(
                "exactframerate={rate} with interlace looks like the field rate: the value is the frame rate{hint}"
            ),
        );
    }
    if let Some(height) = picture.height
        && matches!(height, 240 | 243 | 288 | 540)
    {
        d.report(
            &rules::VIDEO_INTERLACE_RATE,
            m.index,
            line,
            format!(
                "height={height} with interlace looks like one field: the value counts the lines of the whole frame, so write {}",
                height * 2
            ),
        );
    }
}

/// Type N receivers only have to accept the default read offset (ST 2110-21 §7.2).
/// Only progressive video is checked: the interlaced defaults in ST 2110-21:2022
/// Table 1 are misprinted for 525 and 625 lines.
fn read_offset(m: &Media<'_>, line: usize, fmtp: &Fmtp, picture: &Picture, d: &mut Diagnostics) {
    if picture.interlaced {
        return;
    }
    let (Some(troff), Some(height), Some(rate)) = (fmtp.value("TROFF").and_then(digits), picture.height, picture.rate)
    else {
        return;
    };
    let default = tro_default_progressive(height, rate) * 1e6;
    if (troff as f64 - default).abs() >= 1.0 {
        d.report(
            &rules::TROFF_NONDEFAULT,
            m.index,
            line,
            format!(
                "TROFF={troff} is not the default of {default:.0} µs for {height}-line video at {} fps; Type N receivers are only required to accept the default",
                super::fps(rate)
            ),
        );
    }
}

/// RP 2110-24 carriage of 525- and 625-line interlaced video.
fn standard_definition(m: &Media<'_>, line: usize, fmtp: &Fmtp, picture: &Picture, d: &mut Diagnostics) {
    let (Some(height), Some(rate)) = (picture.height, picture.rate) else { return };
    if !picture.interlaced {
        return;
    }
    let (system, heights, ratios) = match (rate.numerator(), rate.denominator()) {
        (30_000, 1001) if height <= 512 => (525, 480..=486, [(10, 11), (40, 33)]),
        (25, 1) if height <= 612 => (625, 576..=576, [(12, 11), (16, 11)]),
        _ => return,
    };
    if let Some(width) = picture.width
        && width != 720
    {
        d.report(
            &rules::VIDEO_SD_WIDTH,
            m.index,
            line,
            format!("width={width}: {system}-line video is sent 720 samples wide"),
        );
    }
    if !heights.contains(&height) {
        let expected = if system == 525 { "480 to 486 lines" } else { "576 lines" };
        d.report(
            &rules::VIDEO_SD_HEIGHT,
            m.index,
            line,
            format!("height={height}: in Standard Mode, {system}-line video is {expected} high"),
        );
    }
    let wanted = format!("PAR={}:{} for 4:3 or PAR={}:{} for 16:9", ratios[0].0, ratios[0].1, ratios[1].0, ratios[1].1);
    let par = fmtp
        .value("PAR")
        .and_then(|v| v.split_once(':'))
        .and_then(|(w, h)| Rational::new(digits(w)?, digits(h)?))
        .map(|r| (r.numerator(), r.denominator()));
    match par {
        Some(par) if ratios.contains(&par) => {}
        Some((w, h)) => {
            d.report(
                &rules::VIDEO_SD_PAR,
                m.index,
                line,
                format!("PAR={w}:{h} is not a {system}-line pixel aspect ratio; signal {wanted}"),
            );
        }
        None if !fmtp.has("PAR") => {
            d.report(
                &rules::VIDEO_SD_PAR,
                m.index,
                line,
                format!("no PAR, so receivers assume square pixels; {system}-line video signals {wanted}"),
            );
        }
        None => {}
    }
}

pub(super) fn describe(m: &Media<'_>) -> (String, Option<f64>) {
    let Some((_, fmtp)) = m.format() else {
        return ("uncompressed video".into(), None);
    };
    let picture = Picture::read(fmtp);
    let scan = super::scan(fmtp);
    let mut parts = Vec::new();
    match (picture.width, picture.height) {
        (Some(w), Some(h)) => parts.push(format!("{w}x{h} {scan}")),
        _ => parts.push(scan.to_string()),
    }
    if let Some(rate) = picture.rate {
        parts.push(format!("{} fps", super::fps(rate)));
    }
    match (fmtp.value("sampling"), fmtp.value("depth")) {
        (Some(sampling), Some("16f")) => parts.push(format!("{sampling} 16-bit float")),
        (Some(sampling), Some(depth)) => parts.push(format!("{sampling} {depth}-bit")),
        (Some(sampling), None) => parts.push(sampling.to_string()),
        _ => {}
    }
    let colour: Vec<&str> = [fmtp.value("colorimetry"), fmtp.value("TCS")].into_iter().flatten().collect();
    if !colour.is_empty() {
        parts.push(colour.join(" "));
    }
    parts.extend(["PM", "TP"].into_iter().filter_map(|name| fmtp.value(name)).map(String::from));
    let bits = picture.payload_bitrate();
    if let Some(bits) = bits {
        parts.push(super::bitrate(bits));
    }
    (parts.join(", "), bits)
}
