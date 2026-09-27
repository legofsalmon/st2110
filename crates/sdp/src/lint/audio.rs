//! ST 2110-30 PCM audio and ST 2110-31 AES3 transparent transport.

use crate::audio::{aes3_level, aes3_samples, payload_limit, pcm_level, samples_per_packet};
use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rational::digits;
use crate::rules;
use crate::stream::Media;

use super::params::{self, Names};

const NAMES: Names<'static> = Names { known: &["channel-order"], strict: false, repeatable: &[] };

pub(super) fn check_pcm(m: &Media<'_>, d: &mut Diagnostics) {
    let Some((map_line, map)) = &m.rtpmap else { return };
    let rate = map.clock_rate;
    let rate_ok = sample_rate(m, *map_line, rate, "ST 2110-30:2025 §6.1", d);
    let channels = channel_count(m, *map_line, map.params.as_deref(), d);
    let bytes_per_sample = if map.encoding.eq_ignore_ascii_case("L16") { 2 } else { 3 };
    if let Some((line, fmtp)) = m.format() {
        params::check(m, line, fmtp, &NAMES, d);
        if let Some(channels) = channels {
            channel_order(m, line, fmtp, channels, false, d);
        }
    }
    let ptime = match packet_time(m) {
        None => {
            d.report(
                &rules::AUDIO_PTIME_MISSING,
                m.index,
                m.line,
                "no a=ptime, so receivers cannot confirm the packet time: 1 ms for level A, 0.125 ms for levels B and C",
            );
            return;
        }
        Some((line, text, None)) => {
            d.report(
                &rules::AUDIO_PTIME,
                m.index,
                line,
                format!("ptime={text} is not a packet time in milliseconds, such as 1 or 0.125"),
            );
            return;
        }
        Some((line, text, Some(ms))) => (line, text, ms),
    };
    let (Some(channels), true) = (channels, rate_ok) else { return };
    let (line, text, ms) = ptime;
    if pcm_level(rate, ms, channels).is_none() {
        let message = match rate {
            44_100 => "44.1 kHz audio fits no ST 2110-30 conformance level: the levels are defined at 48 and 96 kHz, and receivers need only support 48 kHz".to_string(),
            48_000 => format!(
                "48 kHz with {text} ms packets and {channels} channels fits no conformance level: A is 1 ms with up to 8 channels, B is 0.125 ms with up to 8, C is 0.125 ms with 9 to 64"
            ),
            _ => format!(
                "96 kHz with {text} ms packets and {channels} channels fits no conformance level: AX is 1 ms with up to 4 channels, BX is 0.125 ms with up to 8, CX is 0.125 ms with 9 to 32"
            ),
        };
        d.report(&rules::AUDIO_LEVEL, m.index, line, message);
    }
    packet_size(m, line, samples_per_packet(rate, ms), channels, bytes_per_sample, d);
}

pub(super) fn check_aes3(m: &Media<'_>, d: &mut Diagnostics) {
    let Some((map_line, map)) = &m.rtpmap else { return };
    let rate = map.clock_rate;
    let rate_ok = sample_rate(m, *map_line, rate, "ST 2110-31:2022 Table 1", d);
    let subframes = match map.params.as_deref() {
        None => {
            d.report(
                &rules::AES3_CHANNELS,
                m.index,
                *map_line,
                format!("AM824/{rate} gives no channel count: write AM824/{rate}/2, with an even number of subframes"),
            );
            None
        }
        Some(text) => channel_count(m, *map_line, Some(text), d),
    };
    if let Some(n) = subframes
        && n % 2 == 1
    {
        d.report(
            &rules::AES3_CHANNELS,
            m.index,
            *map_line,
            format!("{n} channels: AES3 is carried as subframe pairs, so the count is even"),
        );
    }
    if let Some((line, fmtp)) = m.format() {
        params::check(m, line, fmtp, &NAMES, d);
        if let Some(n) = subframes {
            channel_order(m, line, fmtp, n, true, d);
        }
    }
    let Some((line, text, _)) = packet_time(m) else {
        d.report(
            &rules::AES3_PTIME,
            m.index,
            m.line,
            "no a=ptime: ST 2110-31 senders signal it as 1, 0.12 or 0.08 (ms)",
        );
        return;
    };
    if !rate_ok {
        return;
    }
    let Some(samples) = aes3_samples(rate, text) else {
        let table = if rate == 44_100 { "1.09, 0.14 or 0.09" } else { "1, 0.12 or 0.08" };
        d.report(
            &rules::AES3_PTIME,
            m.index,
            line,
            format!("ptime={text} is not in Table 1, which writes the packet times at {} as {table}", khz(rate)),
        );
        return;
    };
    let Some(n) = subframes else { return };
    if rate == 48_000 && aes3_level(rate, text, n).is_none() {
        d.report(
            &rules::AUDIO_LEVEL,
            m.index,
            line,
            format!(
                "48 kHz with {text} ms packets and {n} subframes fits no ST 2110-31 level: A is 1 ms with up to 6, B is 0.12 ms with up to 8, C is 0.12 ms with up to 60, D is 0.08 ms with up to 80"
            ),
        )
        .cite("ST 2110-31:2022 Table 3");
    }
    packet_size(m, line, samples, n, 4, d);
}

fn sample_rate(m: &Media<'_>, line: usize, rate: u32, reference: &'static str, d: &mut Diagnostics) -> bool {
    if matches!(rate, 48_000 | 44_100 | 96_000) {
        return true;
    }
    d.report(
        &rules::AUDIO_RATE,
        m.index,
        line,
        format!("{rate} Hz is not an ST 2110 sampling rate: 48 kHz, or 44.1 or 96 kHz"),
    )
    .cite(reference);
    false
}

/// The channel count from the `a=rtpmap` encoding parameters; one when there are none.
fn channel_count(m: &Media<'_>, line: usize, params: Option<&str>, d: &mut Diagnostics) -> Option<u16> {
    let Some(text) = params else { return Some(1) };
    let count = digits(text).and_then(|n| u16::try_from(n).ok()).filter(|n| *n > 0);
    if count.is_none() {
        d.report(
            &rules::RTPMAP_SYNTAX,
            m.index,
            line,
            format!("channel count {text} is not a whole number of channels"),
        );
    }
    count
}

/// The `a=ptime` line, its value as written and, when it is a positive number, in milliseconds.
fn packet_time<'a>(m: &Media<'a>) -> Option<(usize, &'a str, Option<f64>)> {
    let (attrs, _) = m.attrs("ptime");
    let attr = attrs.first()?;
    let text = attr.text();
    let ms = text
        .parse::<f64>()
        .ok()
        .filter(|ms| ms.is_finite() && *ms > 0.0 && text.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
    Some((attr.line, text, ms))
}

fn packet_size(m: &Media<'_>, line: usize, samples: u32, channels: u16, bytes_per_sample: u32, d: &mut Diagnostics) {
    let payload = u64::from(samples) * u64::from(channels) * u64::from(bytes_per_sample);
    let maxudp = m.maxudp();
    let limit = payload_limit(maxudp);
    if payload > u64::from(limit) {
        d.report(
            &rules::AUDIO_PACKET_SIZE,
            m.index,
            line,
            format!(
                "{samples} samples × {channels} channels × {bytes_per_sample} bytes is {payload} bytes of payload per packet; a {}-octet datagram holds {limit}",
                maxudp.unwrap_or(1460)
            ),
        );
    }
}

/// Checks `channel-order=SMPTE2110.(<groups>)` against the channel count.
fn channel_order(m: &Media<'_>, line: usize, fmtp: &Fmtp, channels: u16, aes3: bool, d: &mut Diagnostics) {
    let Some(param) = fmtp.get("channel-order") else { return };
    let value = param.value.as_deref().unwrap_or("");
    let mut report = |message: String| {
        d.report(&rules::AUDIO_CHANNEL_ORDER, m.index, line, message);
    };
    let Some((convention, groups)) = value.split_once('.') else {
        report(format!("channel-order={value} is not <convention>.(<groups>), such as SMPTE2110.(ST)"));
        return;
    };
    if convention != "SMPTE2110" {
        report(format!("channel-order uses the {convention} convention; ST 2110-30 receivers expect SMPTE2110"));
        return;
    }
    let Some(inner) = groups.strip_prefix('(').and_then(|g| g.strip_suffix(')')) else {
        report(format!("channel-order={value}: the groups go in parentheses, such as SMPTE2110.(51,ST)"));
        return;
    };
    let mut total = 0;
    for symbol in inner.split(',').map(str::trim) {
        let Some(size) = group_size(symbol, aes3) else {
            let symbols = if aes3 {
                "M, DM, ST, LtRt, 51, 71, 222, SGRP, AES3 or U01 to U64"
            } else {
                "M, DM, ST, LtRt, 51, 71, 222, SGRP or U01 to U64"
            };
            report(format!("channel-order: {symbol} is not a grouping symbol ({symbols})"));
            return;
        };
        total += size;
    }
    let channels = u32::from(channels);
    if total < channels {
        report(format!(
            "channel-order describes {total} channels, but the stream carries {channels}; the rest count as undefined"
        ));
    } else if total > channels {
        report(format!("channel-order describes {total} channels, but the stream carries only {channels}"));
    }
}

/// Channels in one ST 2110-30 grouping symbol (Table 1), or in ST 2110-31's `AES3`.
fn group_size(symbol: &str, aes3: bool) -> Option<u32> {
    match symbol {
        "M" => Some(1),
        "DM" | "ST" | "LtRt" => Some(2),
        "SGRP" => Some(4),
        "51" => Some(6),
        "71" => Some(8),
        "222" => Some(24),
        "AES3" if aes3 => Some(2),
        _ => {
            let number = symbol.strip_prefix('U').filter(|n| n.len() == 2).and_then(digits)?;
            (1..=64).contains(&number).then_some(number as u32)
        }
    }
}

/// A sampling rate for display: `48 kHz`, `44.1 kHz`.
fn khz(rate: u32) -> String {
    if rate.is_multiple_of(1000) { format!("{} kHz", rate / 1000) } else { format!("{} kHz", f64::from(rate) / 1000.0) }
}

/// The groups inside `channel-order=SMPTE2110.(...)`, for display.
fn order(m: &Media<'_>) -> Option<String> {
    let value = m.value("channel-order")?;
    let inner = value.strip_prefix("SMPTE2110.(")?.strip_suffix(')')?;
    Some(inner.to_string())
}

pub(super) fn describe_pcm(m: &Media<'_>) -> (String, Option<f64>) {
    let Some((_, map)) = &m.rtpmap else { return ("PCM audio".into(), None) };
    let rate = map.clock_rate;
    let channels = map.params.as_deref().map_or(Some(1), |p| digits(p).and_then(|n| u16::try_from(n).ok()));
    let bits = if map.encoding.eq_ignore_ascii_case("L16") { 16 } else { 24 };
    let mut parts = vec![format!("{} {}", map.encoding, khz(rate))];
    if let Some(n) = channels {
        let noun = if n == 1 { "channel" } else { "channels" };
        match order(m) {
            Some(groups) => parts.push(format!("{n} {noun} ({groups})")),
            None => parts.push(format!("{n} {noun}")),
        }
    }
    let ptime = packet_time(m).and_then(|(_, text, ms)| Some((text, ms?)));
    if let Some((text, ms)) = ptime {
        parts.push(format!("{text} ms"));
        if let Some(level) = channels.and_then(|n| pcm_level(rate, ms, n)) {
            parts.push(format!("level {level}"));
        }
    }
    let bitrate = channels.map(|n| f64::from(rate) * f64::from(n) * f64::from(bits));
    if let Some(bitrate) = bitrate {
        parts.push(super::bitrate(bitrate));
    }
    (parts.join(", "), bitrate)
}

pub(super) fn describe_aes3(m: &Media<'_>) -> (String, Option<f64>) {
    let Some((_, map)) = &m.rtpmap else { return ("AES3 audio".into(), None) };
    let rate = map.clock_rate;
    let subframes = map.params.as_deref().and_then(digits).and_then(|n| u16::try_from(n).ok());
    let mut parts = vec![format!("{} {}", map.encoding, khz(rate))];
    if let Some(n) = subframes {
        parts.push(format!("{n} subframes ({} AES3 pairs)", n / 2));
    }
    if let Some((_, text, _)) = packet_time(m) {
        parts.push(format!("{text} ms"));
        if let Some(level) = subframes.and_then(|n| aes3_level(rate, text, n)) {
            parts.push(format!("level {level}"));
        }
    }
    // Each AM824 subframe is 32 bits: 8 bits of AES3 flags and 24 bits of audio.
    let bitrate = subframes.map(|n| f64::from(rate) * f64::from(n) * 32.0);
    if let Some(bitrate) = bitrate {
        parts.push(super::bitrate(bitrate));
    }
    (parts.join(", "), bitrate)
}
