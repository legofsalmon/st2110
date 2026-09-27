//! ST 2110-40 ancillary data, ST 2110-41 fast metadata and ST 2110-43 timed text.

use crate::diag::Diagnostics;
use crate::fmtp::Fmtp;
use crate::rules;
use crate::stream::Media;

use super::params::{self, Names};

/// Where ST 2110-40 lists its SDP requirements.
const ANC: &str = "ST 2110-40:2023 §7";
/// The fast metadata standard, whose SDP clause every FMX finding cites.
const FMX: &str = "ST 2110-41:2024";

const ANC_NAMES: Names<'static> = Names {
    known: &["DID_SDID", "VPID_Code", "SSN", "TM", "exactframerate"],
    strict: false,
    repeatable: &["DID_SDID"],
};
const FMX_NAMES: Names<'static> = Names { known: &["SSN", "DIT"], strict: false, repeatable: &[] };
const TTML_NAMES: Names<'static> = Names { known: &["codecs", "charset"], strict: false, repeatable: &[] };

pub(super) fn check_anc(m: &Media<'_>, d: &mut Diagnostics) {
    super::clock_rate(m, d, 90_000, "ST 2110-40:2023");
    let Some((line, fmtp)) = m.format() else {
        d.report(
            &rules::PARAM_MISSING,
            m.index,
            m.line,
            "no a=fmtp line: ST 2110-40:2023 senders give exactframerate and SSN",
        )
        .cite(ANC);
        return;
    };
    params::check(m, line, fmtp, &ANC_NAMES, d);
    if fmtp.has("exactframerate") {
        super::exact_frame_rate(m, d, line, fmtp, ANC);
    } else {
        d.report(
            &rules::PARAM_MISSING,
            m.index,
            line,
            "no exactframerate: ST 2110-40:2023 requires it from every ANC sender, even one with no video to follow",
        )
        .cite(ANC);
    }
    let timing_model = fmtp.get("TM").map(|p| p.value.as_deref().unwrap_or(""));
    if let Some(value) = timing_model
        && !matches!(value, "CTM" | "LLTM")
    {
        d.report(&rules::ANC_TM, m.index, line, format!("TM={value} is not CTM or LLTM"));
    }
    anc_edition(m, line, fmtp, timing_model.is_some(), d);
    for param in fmtp.all("DID_SDID") {
        let value = param.value.as_deref().unwrap_or("");
        if did_sdid(value).is_none() {
            d.report(
                &rules::ANC_PARAM,
                m.index,
                line,
                format!("DID_SDID={value} is not {{0xNN,0xNN}}, such as DID_SDID={{0x61,0x01}}"),
            );
        }
    }
    if let Some(param) = fmtp.get("VPID_Code") {
        let value = param.value.as_deref().unwrap_or("");
        if crate::rational::digits(value).is_none_or(|n| n > 255) {
            d.report(
                &rules::ANC_PARAM,
                m.index,
                line,
                format!("VPID_Code={value} is not a number from 0 to 255 (byte 1 of the ST 352 payload ID)"),
            );
        }
    }
}

/// Senders signal the 2018 edition unless they signal a timing model, which the
/// 2023 edition added.
fn anc_edition(m: &Media<'_>, line: usize, fmtp: &Fmtp, signals_tm: bool, d: &mut Diagnostics) {
    let Some(param) = fmtp.get("SSN") else {
        let expected = if signals_tm {
            "SSN=ST2110-40:2023, as it signals TM"
        } else {
            "SSN=ST2110-40:2018, or SSN=ST2110-40:2023 together with TM"
        };
        d.report(&rules::PARAM_MISSING, m.index, line, format!("no SSN: this stream signals {expected}")).cite(ANC);
        return;
    };
    let value = param.value.as_deref().unwrap_or("");
    let edition = match value {
        "ST2110-40:2018" => 2018,
        "ST2110-40:2023" => 2023,
        "ST2110-40:2021" => {
            d.report(
                &rules::SSN_TYPO,
                m.index,
                line,
                "SSN=ST2110-40:2021 copies a misprint in ST 2110-40:2023; write SSN=ST2110-40:2023",
            );
            2023
        }
        _ => {
            d.report(&rules::SSN, m.index, line, format!("SSN={value} is not ST2110-40:2018 or ST2110-40:2023"))
                .cite(ANC);
            return;
        }
    };
    let problem = match (edition, signals_tm) {
        (2023, false) => "SSN=ST2110-40:2023 goes with TM: add TM=CTM or TM=LLTM, or signal SSN=ST2110-40:2018",
        (2018, true) => "this stream signals TM, so its SSN is ST2110-40:2023",
        _ => return,
    };
    d.report(&rules::SSN, m.index, line, problem).cite(ANC);
}

/// Parses `{0x61,0x01}` into its DID and SDID.
fn did_sdid(value: &str) -> Option<(u8, u8)> {
    let inner = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    let (did, sdid) = inner.split_once(',')?;
    Some((hex_byte(did)?, hex_byte(sdid)?))
}

fn hex_byte(text: &str) -> Option<u8> {
    let text = text.trim();
    let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))?;
    if hex.is_empty() || hex.len() > 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(hex, 16).ok()
}

/// Well-known ANC services, by DID and SDID.
fn service(did: u8, sdid: u8) -> Option<&'static str> {
    match (did, sdid) {
        (0x41, 0x01) => Some("VPID"),
        (0x41, 0x05) => Some("AFD"),
        (0x41, 0x07) => Some("SCTE 104"),
        (0x43, 0x02) => Some("OP-47"),
        (0x60, 0x60) => Some("timecode"),
        (0x61, 0x01) => Some("CEA-708"),
        (0x61, 0x02) => Some("CEA-608"),
        _ => None,
    }
}

pub(super) fn check_fmx(m: &Media<'_>, d: &mut Diagnostics) {
    let Some((line, fmtp)) = m.format() else {
        d.report(&rules::PARAM_MISSING, m.index, m.line, "no a=fmtp line, so SSN is not given").cite(FMX);
        return;
    };
    params::check(m, line, fmtp, &FMX_NAMES, d);
    match fmtp.get("SSN") {
        None => {
            d.report(&rules::PARAM_MISSING, m.index, line, "SSN is required: SSN=ST2110-41:2024").cite(FMX);
        }
        Some(param) => {
            let value = param.value.as_deref().unwrap_or("");
            // The IANA registration spells it SMPTE2110-41:2024.
            if !matches!(value, "ST2110-41:2024" | "SMPTE2110-41:2024") {
                d.report(
                    &rules::SSN,
                    m.index,
                    line,
                    format!("SSN={value}: fast metadata streams signal SSN=ST2110-41:2024, the 2026 edition included"),
                )
                .cite(FMX);
            }
        }
    }
    match fmtp.get("DIT") {
        None => {
            d.report(
                &rules::FMX_DIT,
                m.index,
                line,
                "no DIT: list the data item types the stream carries, such as DIT=100",
            );
        }
        Some(param) => {
            for item in param.value.as_deref().unwrap_or("").split(',') {
                match data_item_type(item) {
                    Err(problem) => {
                        d.report(&rules::FMX_DIT_SYNTAX, m.index, line, format!("DIT: {problem}"));
                    }
                    Ok(value) if (0x30_0000..=0x3F_EFFF).contains(&value) => {
                        d.report(
                            &rules::FMX_DIT,
                            m.index,
                            line,
                            format!("data item type {item} is in the reserved range, 300000 to 3FEFFF"),
                        );
                    }
                    Ok(_) => {}
                }
            }
        }
    }
}

/// Parses one `DIT` entry: 22-bit uppercase hex without `0x`.
fn data_item_type(item: &str) -> Result<u32, String> {
    if item.is_empty() {
        return Err("an empty entry; separate types with single commas".into());
    }
    if item.contains(char::is_whitespace) {
        return Err(format!("`{item}` has a space; write the list without spaces, such as DIT=100,2000A1"));
    }
    if item.starts_with("0x") || item.starts_with("0X") {
        return Err(format!("{item}: write the hex digits without 0x"));
    }
    if !item.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{item} is not a hex number"));
    }
    if item.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(format!("{item}: write hex digits in uppercase, {}", item.to_ascii_uppercase()));
    }
    match u32::from_str_radix(item, 16) {
        Ok(value) if value <= 0x3F_FFFF => Ok(value),
        _ => Err(format!("{item} is over the 22-bit maximum, 3FFFFF")),
    }
}

/// Registered data item types.
fn data_item_name(value: u32) -> Option<&'static str> {
    match value {
        0x00_0100 => Some("ST 2127-2 audio metadata"),
        0x10_0100 => Some("IPMX HDMI InfoFrame"),
        _ => None,
    }
}

pub(super) fn check_ttml(m: &Media<'_>, d: &mut Diagnostics) {
    super::clock_rate(m, d, 90_000, "ST 2110-43:2021 §4.2");
    let (line, fmtp) = match m.format() {
        Some((line, fmtp)) => {
            params::check(m, line, fmtp, &TTML_NAMES, d);
            (line, Some(fmtp))
        }
        None => (m.line, None),
    };
    if !fmtp.is_some_and(|f| f.has("codecs")) {
        d.report(
            &rules::PARAM_MISSING,
            m.index,
            line,
            "no codecs parameter: RFC 8759 requires it, naming the TTML profile, such as codecs=im3t for IMSC 1.2 text",
        )
        .cite("RFC 8759");
    }
}

pub(super) fn describe_anc(m: &Media<'_>) -> String {
    let Some((_, fmtp)) = m.format() else { return "ancillary data".into() };
    let services: Vec<String> = fmtp
        .all("DID_SDID")
        .filter_map(|p| did_sdid(p.value.as_deref()?))
        .map(|(did, sdid)| match service(did, sdid) {
            Some(name) => format!("{name} {did:02X}/{sdid:02X}"),
            None => format!("{did:02X}/{sdid:02X}"),
        })
        .collect();
    let mut parts = vec![if services.is_empty() {
        "ancillary data".to_string()
    } else {
        format!("ancillary data ({})", services.join(", "))
    }];
    if let Some(rate) = fmtp.value("exactframerate").and_then(super::read_frame_rate) {
        parts.push(format!("{} fps", super::fps(rate)));
    }
    if let Some(tm) = fmtp.value("TM") {
        parts.push(tm.to_string());
    }
    parts.join(", ")
}

pub(super) fn describe_fmx(m: &Media<'_>) -> String {
    let Some(list) = m.value("DIT") else { return "fast metadata".into() };
    let types: Vec<String> = list
        .split(',')
        .map(|item| match data_item_type(item).ok().and_then(data_item_name) {
            Some(name) => format!("{item} ({name})"),
            None => item.to_string(),
        })
        .collect();
    format!("fast metadata, DIT {}", types.join(", "))
}

pub(super) fn describe_ttml(m: &Media<'_>) -> String {
    match m.value("codecs") {
        Some(codecs) => format!("TTML timed text ({codecs})"),
        None => "TTML timed text".into(),
    }
}
