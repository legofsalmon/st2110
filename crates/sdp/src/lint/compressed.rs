//! ST 2110-22 constant bit-rate compressed video, such as JPEG XS (RFC 9134).

use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rational::Rational;
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
        // The successor to RFC 9134 (draft-ietf-avtcore-rtp-jpegxs-3ed), which TR-08:2026
        // follows for its FBB levels.
        "fbblevel",
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
    tr08_rate(m, line, fmtp, d);
    tr08_sublevel(m, line, fmtp, d);
    level(m, line, fmtp, d);
}

/// The picture's width, height and frame rate, when the `a=fmtp` line gives all three.
fn picture(fmtp: &Fmtp) -> Option<(u32, u32, Rational)> {
    let number = |name: &str| fmtp.value(name).and_then(|v| v.trim().parse::<u32>().ok()).filter(|n| *n > 0);
    Some((number("width")?, number("height")?, fmtp.value("exactframerate").and_then(super::read_frame_rate)?))
}

/// The bits a pixel that `b=AS`, which counts whole IP packets, spends on the picture.
fn bits_a_pixel(kbps: u64, (width, height, rate): (u32, u32, Rational)) -> f64 {
    kbps as f64 * 1000.0 / (f64::from(width) * f64::from(height) * rate.to_f64())
}

/// Packet headers add a few per cent to the coded rate at the sizes ST 2110-22 uses.
const HEADROOM: f64 = 1.05;

/// VSF TR-08:2026 §8.1.1 codes at most 4 bits a pixel, and a sublevel caps it lower:
/// `b=AS`, which counts whole IP packets, says how many the stream spends.
fn tr08_rate(m: &Media<'_>, line: usize, fmtp: &Fmtp, d: &mut Diagnostics) {
    let (Some(kbps), Some(picture)) = (average_bandwidth(m), picture(fmtp)) else {
        return;
    };
    let (width, height, rate) = picture;
    let (cap, by) = match fmtp.value("sublevel").map(str::to_ascii_lowercase).as_deref() {
        Some("sublev2bpp") => (2.0, "sublevel=Sublev2bpp"),
        Some("sublev3bpp") => (3.0, "sublevel=Sublev3bpp"),
        _ => (4.0, "TR-08"),
    };
    let bits = bits_a_pixel(kbps, picture);
    if bits > cap * HEADROOM {
        d.report(
            &rules::JXSV_BITS,
            m.index,
            line,
            format!(
                "b=AS:{kbps} is {bits:.1} bits a pixel at {width}x{height} and {} fps, but {by} codes at most {cap:.0}, with a few per cent more for packet headers",
                super::fps(rate)
            ),
        );
    }
}

/// VSF TR-08:2026 §8.1.1: "when the bpp is less than or equal to 3bpp, Sublev3bpp shall
/// be used". `b=AS` counts packet headers too, so a stream it puts at 3 bits a pixel or
/// fewer codes fewer still.
fn tr08_sublevel(m: &Media<'_>, line: usize, fmtp: &Fmtp, d: &mut Diagnostics) {
    let (Some(sublevel), Some(kbps), Some(picture)) = (fmtp.value("sublevel"), average_bandwidth(m), picture(fmtp))
    else {
        return;
    };
    let bits = bits_a_pixel(kbps, picture);
    if sublevel.eq_ignore_ascii_case("Sublev4bpp") && bits <= 3.0 {
        d.report(
            &rules::JXSV_SUBLEVEL,
            m.index,
            line,
            format!(
                "sublevel={sublevel}, but b=AS:{kbps} is {bits:.1} bits a pixel: TR-08 signals Sublev3bpp up to 3 (Sublev2bpp in capability sets E and F), and Sublev4bpp only above 3"
            ),
        );
    }
}

/// A JPEG XS level's maxima: width, height, pixels a picture (L_max) and pixels a second
/// (R_s,max).
struct Level {
    name: &'static str,
    width: u32,
    height: u32,
    pixels: u64,
    rate: u64,
}

/// The JPEG XS levels of ISO/IEC 21122-2:2024 Annex A and its Amendment 1, which are not
/// freely published. Width, height and L_max are as SVT-JPEG-XS encodes them, which
/// Wikipedia's table agrees with; R_s,max is Wikipedia's, which agrees with the levels
/// VSF TR-08:2026 Appendix B picks at every rate boundary it tries.
const LEVELS: [Level; 10] = [
    Level { name: "1k-1", width: 1280, height: 5120, pixels: 2_621_440, rate: 83_558_400 },
    Level { name: "2k-1", width: 2048, height: 8192, pixels: 4_194_304, rate: 133_693_440 },
    Level { name: "4k-1", width: 4096, height: 16384, pixels: 8_912_896, rate: 267_386_880 },
    Level { name: "4k-2", width: 4096, height: 16384, pixels: 16_777_216, rate: 534_773_760 },
    Level { name: "4k-3", width: 4096, height: 16384, pixels: 16_777_216, rate: 1_069_547_520 },
    Level { name: "5k-1", width: 5120, height: 16384, pixels: 16_777_216, rate: 1_069_547_520 },
    Level { name: "8k-1", width: 8192, height: 32768, pixels: 35_651_584, rate: 1_069_547_520 },
    Level { name: "8k-2", width: 8192, height: 32768, pixels: 67_108_864, rate: 2_139_095_040 },
    Level { name: "8k-3", width: 8192, height: 32768, pixels: 67_108_864, rate: 4_278_190_080 },
    Level { name: "10k-1", width: 10240, height: 40960, pixels: 104_857_600, rate: 3_342_336_000 },
];

/// The levels VSF TR-08:2026 §8.1.1 allows, lowest first.
const TR08_LEVELS: [&str; 4] = ["1k-1", "2k-1", "4k-2", "8k-2"];

/// The names of the same levels for Bayer images, in the order of [`LEVELS`].
const BAYER_LEVELS: [&str; 10] = [
    "Bayer2k-1",
    "Bayer4k-1",
    "Bayer8k-1",
    "Bayer8k-2",
    "Bayer8k-3",
    "Bayer10k-1",
    "Bayer16k-1",
    "Bayer16k-2",
    "Bayer16k-3",
    "Bayer20k-1",
];

/// The sublevels of the published tables.
const SUBLEVELS: [&str; 8] =
    ["Unrestricted", "Full", "Sublev12bpp", "Sublev9bpp", "Sublev6bpp", "Sublev4bpp", "Sublev3bpp", "Sublev2bpp"];

impl Level {
    fn named(name: &str) -> Option<&'static Level> {
        LEVELS.iter().find(|level| level.name.eq_ignore_ascii_case(name))
    }

    /// What of the picture is over this level's maxima.
    fn excess(&self, (width, height, rate): (u32, u32, Rational)) -> Vec<String> {
        let mut over = Vec::new();
        if width > self.width {
            over.push(format!("width={width} is over its {} pixels a row", self.width));
        }
        if height > self.height {
            over.push(format!("height={height} is over its {} rows", self.height));
        }
        let pixels = u64::from(width) * u64::from(height);
        if pixels > self.pixels {
            over.push(format!("{width}x{height} is {pixels} pixels a picture, over its {}", self.pixels));
        }
        // Exactly: pixels × num ÷ den against R_s,max.
        let (num, den) = (u128::from(rate.numerator()), u128::from(rate.denominator()));
        if u128::from(pixels) * num > u128::from(self.rate) * den {
            over.push(format!(
                "{width}x{height} at {} frames a second is {:.1} million pixels a second, over its {:.1} million",
                super::fps(rate),
                pixels as f64 * rate.to_f64() / 1e6,
                self.rate as f64 / 1e6
            ));
        }
        over
    }
}

/// The `level` and `sublevel` names, the picture against the level's maxima, and TR-08's
/// lowest level that fits. Interlaced video counts a frame's pixels at the frame rate,
/// as `exactframerate` gives it and TR-08 Appendix B counts.
fn level(m: &Media<'_>, line: usize, fmtp: &Fmtp, d: &mut Diagnostics) {
    if let Some(sublevel) = fmtp.value("sublevel")
        && !SUBLEVELS.iter().any(|name| name.eq_ignore_ascii_case(sublevel))
    {
        d.report(
            &rules::JXSV_LEVEL,
            m.index,
            line,
            format!("sublevel={sublevel} is not a sublevel the JPEG XS tables name, such as Sublev3bpp or Sublev6bpp"),
        );
    }
    let Some(name) = fmtp.value("level") else { return };
    // Bayer levels count the sensor's sampling grid points, which the SDP file's width
    // and height do not give, so only their names are checked.
    let bayer = BAYER_LEVELS.iter().any(|bayer| bayer.eq_ignore_ascii_case(name));
    let level = Level::named(name);
    if level.is_none() && !bayer && !name.eq_ignore_ascii_case("Unrestricted") {
        d.report(
            &rules::JXSV_LEVEL,
            m.index,
            line,
            format!("level={name} is not a level the JPEG XS tables name, such as 2k-1 or 4k-2"),
        );
        return;
    }
    let (Some(level), Some(picture)) = (level, picture(fmtp)) else { return };
    let over = level.excess(picture);
    if !over.is_empty() {
        d.report(
            &rules::JXSV_LEVEL,
            m.index,
            line,
            format!("level={name} does not fit the picture, by the published level tables: {}", over.join("; ")),
        );
        return;
    }
    let signalled = TR08_LEVELS.iter().position(|l| *l == level.name);
    let lowest = TR08_LEVELS.iter().position(|l| Level::named(l).is_some_and(|l| l.excess(picture).is_empty()));
    if let (Some(signalled), Some(lowest)) = (signalled, lowest)
        && lowest < signalled
    {
        let (width, height, rate) = picture;
        d.report(
            &rules::JXSV_LEVEL_LOWEST,
            m.index,
            line,
            format!(
                "level={name}, but {width}x{height} at {} frames a second fits level {}, which is lower: TR-08 asks for the lowest level that fits",
                super::fps(rate),
                TR08_LEVELS[lowest]
            ),
        );
    }
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
