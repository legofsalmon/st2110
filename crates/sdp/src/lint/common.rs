//! ST 2110-10 checks that apply to every stream: RTP, clocks, addressing and the
//! parameters every essence shares.

use std::net::IpAddr;

use crate::clock::{MediaClock, RefClock};
use crate::diag::Diagnostics;
use crate::rational::digits;
use crate::rules;
use crate::sdp::parse_source_filter;
use crate::stream::{Essence, Media, same_address};

pub(super) fn check(m: &Media<'_>, d: &mut Diagnostics) {
    rtp(m, d);
    reference_clock(m, d);
    media_clock(m, d);
    source_filter(m, d);
    shared_parameters(m, d);
}

fn rtp(m: &Media<'_>, d: &mut Diagnostics) {
    let Some(mline) = &m.mline else { return };
    if mline.port == 0 {
        d.report(&rules::MEDIA_DISABLED, m.index, m.line, "port 0: this media section is disabled");
    }
    if mline.proto != "RTP/AVP" {
        d.report(
            &rules::RTP_PROFILE,
            m.index,
            m.line,
            format!("protocol {} is not RTP/AVP, which ST 2110 streams use", mline.proto),
        );
    }
    if mline.formats.len() > 1 {
        d.report(
            &rules::RTP_SINGLE_FORMAT,
            m.index,
            m.line,
            format!("{} payload types listed; only the first, {}, is checked", mline.formats.len(), mline.formats[0]),
        );
    }
    let format = &mline.formats[0];
    match digits(format) {
        Some(96..=127) => {}
        Some(pt) => {
            d.report(
                &rules::RTP_PAYLOAD_TYPE,
                m.index,
                m.line,
                format!("payload type {pt} is outside the dynamic range 96 to 127"),
            );
        }
        None => {
            d.report(
                &rules::RTP_PAYLOAD_TYPE,
                m.index,
                m.line,
                format!("format {format} is not an RTP payload type number"),
            );
        }
    }
}

fn reference_clock(m: &Media<'_>, d: &mut Diagnostics) {
    let (attrs, session_level) = m.attrs("ts-refclk");
    if attrs.is_empty() {
        d.report(
            &rules::TS_REFCLK_MISSING,
            m.index,
            m.line,
            "no a=ts-refclk, so receivers cannot tell which clock the timestamps follow",
        );
        return;
    }
    if session_level {
        d.report(
            &rules::CLOCK_SESSION_LEVEL,
            m.index,
            attrs[0].line,
            "a=ts-refclk is only at session level; repeat it in each media section",
        );
    }
    for attr in &attrs {
        let line = attr.line;
        match RefClock::parse(attr.text()) {
            Err(problem) => {
                d.report(&rules::TS_REFCLK_SYNTAX, m.index, line, problem);
            }
            Ok(RefClock::Ptp { version, domain, traceable, .. }) => {
                if version.eq_ignore_ascii_case("IEEE1588-2019") {
                    d.report(
                        &rules::TS_REFCLK_PTP_VERSION,
                        m.index,
                        line,
                        "IEEE1588-2019: ST 2110-10:2022 and NMOS IS-04 name the version IEEE1588-2008, and receivers may not match anything else",
                    );
                } else if !version.eq_ignore_ascii_case("IEEE1588-2008") {
                    d.report(
                        &rules::TS_REFCLK_NOT_PTP,
                        m.index,
                        line,
                        format!("{version} is not the PTP that ST 2110 uses (ST 2059-2, an IEEE1588-2008 profile)"),
                    );
                }
                match domain {
                    None if !traceable => {
                        d.report(
                            &rules::TS_REFCLK_DOMAIN,
                            m.index,
                            line,
                            "no PTP domain, so receivers cannot check they follow the sender's domain",
                        );
                    }
                    Some(domain) if domain > 127 => {
                        d.report(
                            &rules::TS_REFCLK_DOMAIN,
                            m.index,
                            line,
                            format!("PTP domain {domain} is outside ST 2059-2's range of 0 to 127"),
                        );
                    }
                    _ => {}
                }
            }
            Ok(RefClock::LocalMac { .. }) => {
                d.report(
                    &rules::TS_REFCLK_LOCALMAC,
                    m.index,
                    line,
                    "localmac: the sender is not locked to PTP, so its timestamps cannot be aligned with other sources",
                );
            }
            Ok(RefClock::Other { value }) => {
                d.report(
                    &rules::TS_REFCLK_NOT_PTP,
                    m.index,
                    line,
                    format!("ts-refclk:{value}: ST 2110 streams reference PTP, or localmac when there is none"),
                );
            }
        }
    }
}

fn media_clock(m: &Media<'_>, d: &mut Diagnostics) {
    let (attrs, session_level) = m.attrs("mediaclk");
    if attrs.is_empty() {
        d.report(
            &rules::MEDIACLK_MISSING,
            m.index,
            m.line,
            "no a=mediaclk; ST 2110 streams declare a=mediaclk:direct=0",
        );
        return;
    }
    if session_level {
        d.report(
            &rules::CLOCK_SESSION_LEVEL,
            m.index,
            attrs[0].line,
            "a=mediaclk is only at session level; repeat it in each media section",
        );
    }
    for attr in &attrs {
        let line = attr.line;
        match MediaClock::parse(attr.text()) {
            Err(problem) => {
                d.report(&rules::MEDIACLK_VALUE, m.index, line, problem);
            }
            Ok(MediaClock::Direct { offset: Some(0) }) => {}
            Ok(MediaClock::Direct { offset: Some(offset) }) => {
                d.report(
                    &rules::MEDIACLK_OFFSET,
                    m.index,
                    line,
                    format!(
                        "RTP clock offset {offset}: ST 2110 requires direct=0; a 2110 receiver assumes zero and will misalign this stream"
                    ),
                );
            }
            Ok(MediaClock::Direct { offset: None }) => {
                d.report(&rules::MEDIACLK_OFFSET_IMPLICIT, m.index, line, "write the offset out: a=mediaclk:direct=0");
            }
            Ok(MediaClock::Sender) => {
                d.report(
                    &rules::MEDIACLK_SENDER,
                    m.index,
                    line,
                    "mediaclk:sender: the media clock is not locked to the reference clock",
                );
            }
            Ok(MediaClock::Other { value }) => {
                d.report(
                    &rules::MEDIACLK_VALUE,
                    m.index,
                    line,
                    format!("mediaclk:{value}: ST 2110 uses direct=0, or sender"),
                );
            }
        }
    }
}

fn source_filter(m: &Media<'_>, d: &mut Diagnostics) {
    let Some((_, connection)) = &m.connection else { return };
    let Some(ip) = connection.ip.filter(IpAddr::is_multicast) else { return };
    let (attrs, _) = m.attrs("source-filter");
    if attrs.is_empty() {
        d.report(
            &rules::SOURCE_FILTER_MISSING,
            m.index,
            m.line,
            format!("multicast {ip} has no a=source-filter, so receivers join any source rather than the sender's"),
        );
        return;
    }
    let mut matched = false;
    let mut malformed = false;
    for attr in &attrs {
        let filter = match parse_source_filter(attr.text()) {
            Ok(filter) => filter,
            Err(problem) => {
                malformed = true;
                d.report(&rules::SOURCE_FILTER_SYNTAX, m.index, attr.line, problem);
                continue;
            }
        };
        let destination = filter.destination == "*" || same_address(&filter.destination, &connection.address);
        let family = filter.addr_type == "*" || filter.addr_type == connection.addr_type;
        if destination && family {
            matched = true;
            if !filter.include {
                d.report(
                    &rules::SOURCE_FILTER_MISSING,
                    m.index,
                    attr.line,
                    "the filter excludes sources (excl); ST 2110 receivers expect incl with the sender's address",
                );
            }
        }
    }
    if !matched && !malformed {
        d.report(
            &rules::SOURCE_FILTER_MISMATCH,
            m.index,
            attrs[0].line,
            format!("no a=source-filter names this stream's destination, {}", connection.address),
        );
    }
}

fn shared_parameters(m: &Media<'_>, d: &mut Diagnostics) {
    let is_2110 = m.essence != Essence::Unknown;
    let Some((line, fmtp)) = m.format() else {
        if is_2110 {
            d.report(
                &rules::TSMODE_ABSENT,
                m.index,
                m.line,
                "no TSMODE, so the timestamps count as NEW (made at egress), not as sampling instants",
            );
        }
        return;
    };
    if let Some(param) = fmtp.get("MAXUDP") {
        let value = param.value.as_deref().unwrap_or("");
        match digits(value) {
            None => {
                d.report(&rules::MAXUDP, m.index, line, format!("MAXUDP={value} is not a whole number of octets"));
            }
            Some(octets) if octets > 8960 => {
                d.report(
                    &rules::MAXUDP,
                    m.index,
                    line,
                    format!("MAXUDP={octets} is over the 8960-octet extended UDP size limit"),
                );
            }
            Some(octets) if octets > 1460 => {
                d.report(
                    &rules::MAXUDP_EXTENDED,
                    m.index,
                    line,
                    format!("MAXUDP={octets}: receivers are only required to accept datagrams up to 1460 octets"),
                );
            }
            Some(_) => {}
        }
    }
    match fmtp.get("TSMODE") {
        None if is_2110 => {
            d.report(
                &rules::TSMODE_ABSENT,
                m.index,
                line,
                "no TSMODE, so the timestamps count as NEW (made at egress), not as sampling instants",
            );
        }
        Some(param) => {
            let value = param.value.as_deref().unwrap_or("");
            if !matches!(value, "SAMP" | "PRES" | "NEW") {
                d.report(&rules::TSMODE, m.index, line, format!("TSMODE={value} is not SAMP, PRES or NEW"));
            }
        }
        None => {}
    }
    if let Some(param) = fmtp.get("TSDELAY") {
        let value = param.value.as_deref().unwrap_or("");
        if digits(value).is_none() {
            d.report(&rules::TSDELAY, m.index, line, format!("TSDELAY={value} is not a whole number of microseconds"));
        }
    }
    for (name, unit) in [("TROFF", "microseconds"), ("CMAX", "packets")] {
        if let Some(param) = fmtp.get(name) {
            let value = param.value.as_deref().unwrap_or("");
            if digits(value).is_none_or(|n| n == 0) {
                d.report(
                    &rules::SHAPING_PARAM,
                    m.index,
                    line,
                    format!("{name}={value} is not a positive whole number of {unit}"),
                );
            }
        }
    }
}
