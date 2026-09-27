//! The checks, grouped by the standard they come from.

mod audio;
mod common;
mod compressed;
mod data;
mod groups;
mod params;
mod video;

use crate::Rational;
use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rational::{FrameRateError, Notation, parse_frame_rate};
use crate::rules;
use crate::sdp::SessionDescription;
use crate::stream::{Essence, Media};

pub(crate) fn run(sdp: &SessionDescription, media: &[Media<'_>], d: &mut Diagnostics) {
    groups::check(sdp, media, d);
    for m in media {
        common::check(m, d);
        match m.essence {
            Essence::Video => video::check(m, d),
            Essence::CompressedVideo => compressed::check(m, d),
            Essence::Audio => audio::check_pcm(m, d),
            Essence::Aes3 => audio::check_aes3(m, d),
            Essence::Ancillary => data::check_anc(m, d),
            Essence::FastMetadata => data::check_fmx(m, d),
            Essence::TimedText => data::check_ttml(m, d),
            Essence::Sdi => clock_rate(m, d, 27_000_000, "ST 2022-8:2019"),
            Essence::Unknown => {
                if let Some((line, map)) = &m.rtpmap {
                    let media = m.mline.as_ref().map_or("", |l| l.media.as_str());
                    d.report(
                        &rules::ESSENCE_UNKNOWN,
                        m.index,
                        *line,
                        format!("{media}/{} is not an ST 2110 format; only the ST 2110-10 checks apply", map.encoding),
                    );
                }
            }
        }
    }
}

/// A one-line description of the stream's format and, where exact, its payload bit rate.
pub(crate) fn describe(m: &Media<'_>) -> (String, Option<f64>) {
    match m.essence {
        Essence::Video => video::describe(m),
        Essence::CompressedVideo => compressed::describe(m),
        Essence::Audio => audio::describe_pcm(m),
        Essence::Aes3 => audio::describe_aes3(m),
        Essence::Ancillary => (data::describe_anc(m), None),
        Essence::FastMetadata => (data::describe_fmx(m), None),
        Essence::TimedText => (data::describe_ttml(m), None),
        Essence::Sdi => ("ST 2022-6 SDI over IP".into(), None),
        Essence::Unknown => match &m.rtpmap {
            Some((_, map)) => (format!("{}/{}", map.encoding, map.clock_rate), None),
            None => ("unknown format".into(), None),
        },
    }
}

/// Checks the `a=rtpmap` clock rate against the rate the essence standard fixes.
fn clock_rate(m: &Media<'_>, d: &mut Diagnostics, expected: u32, reference: &'static str) {
    if let Some((line, map)) = &m.rtpmap
        && map.clock_rate != expected
    {
        d.report(
            &rules::RTP_CLOCK_RATE,
            m.index,
            *line,
            format!("{}/{}: the RTP clock must run at {expected} Hz", map.encoding, map.clock_rate),
        )
        .cite(reference);
    }
}

/// Checks an `exactframerate` value, returning the rate when it can be read.
fn frame_rate(
    m: &Media<'_>,
    d: &mut Diagnostics,
    line: usize,
    text: &str,
    reference: &'static str,
) -> Option<Rational> {
    match parse_frame_rate(text) {
        Ok((rate, Notation::Canonical)) => Some(rate),
        Ok((rate, Notation::NotCanonical)) => {
            d.report(&rules::FRAME_RATE_FORM, m.index, line, format!("exactframerate={text}: write {rate}"))
                .cite(reference);
            Some(rate)
        }
        Err(FrameRateError::Decimal(guess)) => {
            let hint = guess.map_or_else(|| "a whole number or a ratio".to_string(), |r| r.to_string());
            d.report(&rules::FRAME_RATE, m.index, line, format!("exactframerate={text} is a decimal; write {hint}"))
                .cite(reference);
            guess
        }
        Err(FrameRateError::Invalid) => {
            d.report(
                &rules::FRAME_RATE,
                m.index,
                line,
                format!("exactframerate={text} is not a whole number or a ratio such as 60000/1001"),
            )
            .cite(reference);
            None
        }
    }
}

/// Checks the `exactframerate` parameter when present, returning the rate when it can be read.
fn exact_frame_rate(
    m: &Media<'_>,
    d: &mut Diagnostics,
    line: usize,
    fmtp: &Fmtp,
    reference: &'static str,
) -> Option<Rational> {
    let param = fmtp.get("exactframerate")?;
    match &param.value {
        Some(text) => frame_rate(m, d, line, text, reference),
        None => {
            d.report(&rules::PARAM_VALUE, m.index, line, "exactframerate needs a value, such as 50 or 60000/1001")
                .cite(reference);
            None
        }
    }
}

/// Reads a frame rate without reporting anything, for stream summaries.
fn read_frame_rate(text: &str) -> Option<Rational> {
    match parse_frame_rate(text) {
        Ok((rate, _)) => Some(rate),
        Err(FrameRateError::Decimal(guess)) => guess,
        Err(FrameRateError::Invalid) => None,
    }
}

/// Checks the ST 2110-21 sender type that ST 2110-20 and -22 streams signal with `TP`.
fn sender_type(m: &Media<'_>, d: &mut Diagnostics, line: usize, fmtp: &Fmtp, reference: &'static str) {
    const TYPES: [&str; 3] = ["2110TPN", "2110TPNL", "2110TPW"];
    let Some(param) = fmtp.get("TP") else {
        d.report(
            &rules::TP,
            m.index,
            line,
            "no TP: senders name their ST 2110-21 type with TP=2110TPN, 2110TPNL or 2110TPW",
        )
        .cite(reference);
        return;
    };
    let value = param.value.as_deref().unwrap_or("");
    let Some(standard) = TYPES.into_iter().find(|t| t.eq_ignore_ascii_case(value)) else {
        d.report(&rules::TP, m.index, line, format!("TP={value} is not 2110TPN, 2110TPNL or 2110TPW")).cite(reference);
        return;
    };
    if standard != value {
        d.report(&rules::TP, m.index, line, format!("TP={value}: the standard spells it {standard}")).cite(reference);
    }
    if standard == "2110TPW" {
        d.report(
            &rules::TP_WIDE,
            m.index,
            line,
            "TP=2110TPW: a wide sender, which narrow (Type N) receivers are not required to accept",
        );
    }
}

/// `progressive`, `interlaced` or `PsF`, from the `interlace` and `segmented` flags.
fn scan(fmtp: &Fmtp) -> &'static str {
    match (fmtp.has("interlace"), fmtp.has("segmented")) {
        (true, true) => "PsF",
        (true, false) => "interlaced",
        (false, _) => "progressive",
    }
}

/// Frames per second for display: `50`, `59.94`, `23.98`.
fn fps(rate: Rational) -> String {
    if rate.is_integer() {
        return rate.to_string();
    }
    let text = format!("{:.2}", rate.to_f64());
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// A bit rate for display: `2.07 Gb/s`, `9.22 Mb/s`.
fn bitrate(bits_per_second: f64) -> String {
    if bits_per_second >= 1e9 {
        format!("{:.2} Gb/s", bits_per_second / 1e9)
    } else if bits_per_second >= 1e6 {
        format!("{:.2} Mb/s", bits_per_second / 1e6)
    } else {
        format!("{:.0} kb/s", bits_per_second / 1e3)
    }
}
