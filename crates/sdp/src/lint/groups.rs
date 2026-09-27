//! Grouping: ST 2022-7 redundancy (`DUP`), RP 2110-23 multi-stream video and `FID`.

use crate::diag::Diagnostics;
use crate::rules;
use crate::sdp::SessionDescription;
use crate::stream::{Essence, Media, same_address};

pub(super) fn check(sdp: &SessionDescription, media: &[Media<'_>], d: &mut Diagnostics) {
    for m in media {
        for attr in m.section.attributes_named("group") {
            d.report(
                &rules::GROUP_SYNTAX,
                m.index,
                attr.line,
                "a=group belongs at session level, before the first m= line",
            );
        }
    }
    for (i, m) in media.iter().enumerate() {
        if let Some(mid) = &m.mid
            && media[..i].iter().any(|earlier| earlier.mid.as_ref() == Some(mid))
        {
            let line = m.section.attribute("mid").map_or(m.line, |a| a.line);
            d.report(
                &rules::MID_DUPLICATE,
                m.index,
                line,
                format!("mid {mid} is already used by an earlier media section"),
            );
        }
    }
    for attr in sdp.session.attributes_named("group") {
        let mut words = attr.text().split_whitespace();
        let Some(semantics) = words.next() else {
            d.add(&rules::GROUP_SYNTAX, "a=group needs semantics and mids, such as a=group:DUP primary secondary")
                .at(attr.line);
            continue;
        };
        let mids: Vec<&str> = words.collect();
        if mids.is_empty() {
            d.add(&rules::GROUP_SYNTAX, format!("a=group:{semantics} names no streams")).at(attr.line);
            continue;
        }
        let mut members = Vec::new();
        for mid in &mids {
            match media.iter().find(|m| m.mid.as_deref() == Some(*mid)) {
                Some(m) => members.push(m),
                None => {
                    d.add(
                        &rules::GROUP_MID_MISSING,
                        format!("a=group:{semantics} names {mid}, but no media section has a=mid:{mid}"),
                    )
                    .at(attr.line);
                }
            }
        }
        match semantics.to_ascii_uppercase().as_str() {
            "DUP" => dup(attr.line, mids.len(), &members, d),
            "MULTI-2SI" | "MULTI-SD" | "PHASED" => multistream(semantics, attr.line, mids.len(), &members, d),
            "FID" => {
                for m in members.iter().filter(|m| m.essence == Essence::Ancillary) {
                    d.report(
                        &rules::FID_ANC,
                        m.index,
                        attr.line,
                        format!("{} is an ANC stream, which ST 2110-40 keeps out of FID groups", mid(m)),
                    );
                }
            }
            _ => {}
        }
    }
}

fn mid<'a>(m: &'a Media<'_>) -> &'a str {
    m.mid.as_deref().unwrap_or("?")
}

fn dup(line: usize, named: usize, members: &[&Media<'_>], d: &mut Diagnostics) {
    if named < 2 {
        d.add(&rules::DUP_GROUP, "a=group:DUP needs at least two streams, one per ST 2022-7 leg").at(line);
        return;
    }
    let Some((first, rest)) = members.split_first() else { return };
    for other in rest {
        if let Some(difference) = leg_difference(first, other) {
            d.report(
                &rules::DUP_MISMATCH,
                other.index,
                other.line,
                format!("leg {} differs from leg {}: {difference}", mid(other), mid(first)),
            );
        }
        let destinations = match (&first.connection, &other.connection) {
            (Some((_, a)), Some((_, b))) if same_address(&a.address, &b.address) => Some(a.address.as_str()),
            _ => None,
        };
        if let (Some(destination), Some(source), Some(other_source)) = (destinations, first.source(), other.source())
            && same_address(&source, &other_source)
        {
            d.report(
                &rules::DUP_ADDRESSING,
                other.index,
                other.line,
                format!(
                    "legs {} and {} share destination {destination} and source {source}; give them different source or destination addresses",
                    mid(first),
                    mid(other)
                ),
            );
        }
        if let (Some(a), Some(b)) = (first.reference_clock(), other.reference_clock())
            && a != b
        {
            d.report(
                &rules::DUP_REFCLK,
                other.index,
                other.line,
                format!("legs {} and {} name different reference clocks", mid(first), mid(other)),
            );
        }
    }
}

/// Describes the first way two legs differ, if they do.
fn leg_difference(a: &Media<'_>, b: &Media<'_>) -> Option<String> {
    let media = |m: &Media<'_>| m.mline.as_ref().map(|l| l.media.clone()).unwrap_or_default();
    if media(a) != media(b) {
        return Some(format!("media type {} against {}", media(b), media(a)));
    }
    if a.payload_type != b.payload_type {
        let pt = |m: &Media<'_>| m.payload_type.map_or("none".to_string(), |p| p.to_string());
        return Some(format!("payload type {} against {}", pt(b), pt(a)));
    }
    let map = |m: &Media<'_>| {
        m.rtpmap.as_ref().map(|(_, r)| {
            let params = r.params.as_deref().map(|p| format!("/{p}")).unwrap_or_default();
            format!("{}/{}{params}", r.encoding.to_ascii_lowercase(), r.clock_rate)
        })
    };
    if map(a) != map(b) {
        return Some(format!(
            "rtpmap {} against {}",
            map(b).unwrap_or_else(|| "none".into()),
            map(a).unwrap_or_else(|| "none".into())
        ));
    }
    let params = |m: &Media<'_>| {
        let mut list: Vec<String> = m
            .fmtp
            .as_ref()
            .map(|(_, f)| {
                f.params
                    .iter()
                    .map(|p| match &p.value {
                        Some(v) => format!("{}={v}", p.name.to_ascii_lowercase()),
                        None => p.name.to_ascii_lowercase(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        list.sort();
        list
    };
    let (pa, pb) = (params(a), params(b));
    if let Some(extra) = pb.iter().find(|p| !pa.contains(p)) {
        return Some(format!("fmtp has {extra}, which the other leg lacks"));
    }
    if let Some(missing) = pa.iter().find(|p| !pb.contains(p)) {
        return Some(format!("fmtp lacks {missing}"));
    }
    None
}

fn multistream(semantics: &str, line: usize, named: usize, members: &[&Media<'_>], d: &mut Diagnostics) {
    let semantics_upper = semantics.to_ascii_uppercase();
    if semantics_upper == "MULTI-SD" {
        d.add(
            &rules::MULTISTREAM_DEPRECATED,
            "MULTI-SD (square division) is deprecated for new designs; use MULTI-2SI",
        )
        .at(line);
    }
    if semantics_upper == "MULTI-2SI" && named != 4 && named != 16 {
        d.add(
            &rules::MULTISTREAM_COUNT,
            format!(
                "a=group:MULTI-2SI has {named} streams; 2SI splits a picture into 4 (2160 lines) or 16 (4320 lines)"
            ),
        )
        .at(line);
    }
    for (i, m) in members.iter().enumerate() {
        let Some((_, connection)) = &m.connection else { continue };
        let earlier = members[..i]
            .iter()
            .find(|e| e.connection.as_ref().is_some_and(|(_, c)| same_address(&c.address, &connection.address)));
        if let Some(earlier) = earlier {
            d.report(
                &rules::MULTISTREAM_ADDRESSES,
                m.index,
                m.line,
                format!(
                    "{} reuses {} from {}; each stream of a {semantics} group needs its own multicast address",
                    mid(m),
                    connection.address,
                    mid(earlier)
                ),
            );
        }
    }
}
