//! RFC 8866 session descriptions.
//!
//! The parser is lenient on purpose: it records each problem as a diagnostic and
//! keeps going, so one bad line never hides the rest of the report.

use std::net::IpAddr;

use crate::diag::{Diagnostic, Diagnostics};
use crate::rational::digits;
use crate::rules;

/// One `<type>=<value>` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Line number in the input, counting from 1.
    pub line: usize,
    /// The type letter, such as `a`, `c` or `m`.
    pub kind: char,
    /// Everything after the `=`.
    pub value: String,
}

/// An `a=` line split into its name and optional value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    /// Line number in the input, counting from 1.
    pub line: usize,
    /// The attribute name, such as `fmtp`.
    pub name: &'a str,
    /// The text after the first `:`, if any.
    pub value: Option<&'a str>,
}

impl<'a> Attribute<'a> {
    fn new(field: &'a Field) -> Self {
        match field.value.split_once(':') {
            Some((name, value)) => Self { line: field.line, name, value: Some(value) },
            None => Self { line: field.line, name: &field.value, value: None },
        }
    }

    /// The value with surrounding whitespace removed, or `""` when there is none.
    pub fn text(&self) -> &'a str {
        self.value.unwrap_or_default().trim()
    }
}

/// The session-level lines, or the lines of one media section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Section {
    /// Lines in input order. A media section starts with its `m=` line.
    pub fields: Vec<Field>,
}

impl Section {
    /// Lines of one type.
    pub fn fields_of(&self, kind: char) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.kind == kind)
    }

    /// The first line of one type.
    pub fn field(&self, kind: char) -> Option<&Field> {
        self.fields_of(kind).next()
    }

    /// Every `a=` line.
    pub fn attributes(&self) -> impl Iterator<Item = Attribute<'_>> {
        self.fields_of('a').map(Attribute::new)
    }

    /// The `a=` lines with this name, compared case-insensitively.
    pub fn attributes_named<'s>(&'s self, name: &str) -> impl Iterator<Item = Attribute<'s>> {
        self.attributes().filter(move |a| a.name.eq_ignore_ascii_case(name))
    }

    /// The first `a=` line with this name.
    pub fn attribute(&self, name: &str) -> Option<Attribute<'_>> {
        self.attributes_named(name).next()
    }
}

/// A session description: the session-level part and its media sections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionDescription {
    /// Session-level lines.
    pub session: Section,
    /// Media sections, each starting with its `m=` line.
    pub media: Vec<Section>,
}

/// Parses a session description and reports structural problems.
pub fn parse(text: &str) -> (SessionDescription, Vec<Diagnostic>) {
    let mut diagnostics = Diagnostics::default();
    let sdp = parse_into(text, &mut diagnostics);
    (sdp, diagnostics.into_sorted())
}

const KNOWN_TYPES: &str = "vosiuepcbtrzkam";

/// Position of a session-level line type in RFC 8866's order.
fn session_rank(kind: char) -> usize {
    match kind {
        'v' => 0,
        'o' => 1,
        's' => 2,
        'i' => 3,
        'u' => 4,
        'e' => 5,
        'p' => 6,
        'c' => 7,
        'b' => 8,
        't' | 'r' | 'z' => 9,
        'k' => 10,
        _ => 11,
    }
}

/// Position of a media-level line type in RFC 8866's order; `None` for session-only types.
fn media_rank(kind: char) -> Option<usize> {
    match kind {
        'i' => Some(1),
        'c' => Some(2),
        'b' => Some(3),
        'k' => Some(4),
        'a' => Some(5),
        _ => None,
    }
}

pub(crate) fn parse_into(text: &str, d: &mut Diagnostics) -> SessionDescription {
    let mut sdp = SessionDescription::default();
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let end = lines.iter().rposition(|l| !l.trim().is_empty()).map_or(0, |i| i + 1);

    let mut in_media = false;
    // The highest-ranked line type so far in the current section, for order checks.
    let mut highest: Option<(usize, char)> = None;
    let mut seen_time = false;

    for (i, raw) in lines[..end].iter().enumerate() {
        let line = i + 1;
        if raw.trim().is_empty() {
            d.add(&rules::SDP_BLANK_LINE, "blank line inside the description").at(line);
            continue;
        }
        let Some((kind, value)) = split_line(raw, line, d) else { continue };
        if !KNOWN_TYPES.contains(kind) {
            d.add(&rules::SDP_UNKNOWN_TYPE, format!("`{kind}=` is not an SDP line type")).at(line);
            continue;
        }
        if kind == 'm' {
            in_media = true;
            highest = None;
            sdp.media.push(Section::default());
        } else if in_media {
            match media_rank(kind) {
                None => {
                    d.add(
                        &rules::SDP_ORDER,
                        format!("`{kind}=` is a session-level line but sits inside a media section"),
                    )
                    .at(line);
                }
                Some(rank) => check_rank(rank, kind, line, &mut highest, d),
            }
        } else {
            if matches!(kind, 'r' | 'z') && !seen_time {
                d.add(&rules::SDP_ORDER, format!("`{kind}=` belongs after a `t=` line")).at(line);
            }
            seen_time |= kind == 't';
            check_rank(session_rank(kind), kind, line, &mut highest, d);
        }
        let field = Field { line, kind, value: value.to_string() };
        match sdp.media.last_mut() {
            Some(section) if in_media => section.fields.push(field),
            _ => sdp.session.fields.push(field),
        }
    }
    check_structure(&sdp, d);
    sdp
}

fn check_rank(rank: usize, kind: char, line: usize, highest: &mut Option<(usize, char)>, d: &mut Diagnostics) {
    match *highest {
        Some((top, top_kind)) if rank < top => {
            d.add(&rules::SDP_ORDER, format!("`{kind}=` comes after `{top_kind}=`, but RFC 8866 puts it first"))
                .at(line);
        }
        _ => *highest = Some((rank, kind)),
    }
}

/// Splits `x=value`, reporting malformed lines. Returns `None` for lines that cannot be used.
fn split_line<'a>(raw: &'a str, line: usize, d: &mut Diagnostics) -> Option<(char, &'a str)> {
    let kind = raw.chars().next()?;
    let rest = &raw[kind.len_utf8()..];
    let lowercase = kind.is_ascii_lowercase();
    if let Some(value) = rest.strip_prefix('=') {
        if !lowercase {
            d.add(&rules::SDP_SYNTAX, format!("`{kind}` is not a line type: types are one lowercase letter")).at(line);
            return None;
        }
        if value.starts_with(char::is_whitespace) && !(kind == 's' && value == " ") {
            d.add(&rules::SDP_SYNTAX, "no space is allowed after `=`").at(line);
            return Some((kind, value.trim_start()));
        }
        return Some((kind, value));
    }
    if let Some(value) = rest.trim_start().strip_prefix('=')
        && lowercase
    {
        d.add(&rules::SDP_SYNTAX, "no space is allowed around `=`").at(line);
        return Some((kind, value.trim_start()));
    }
    d.add(&rules::SDP_SYNTAX, "not a `<type>=<value>` line").at(line);
    None
}

fn check_structure(sdp: &SessionDescription, d: &mut Diagnostics) {
    let session = &sdp.session;
    match session.fields.first() {
        Some(first) if first.kind == 'v' => {
            if first.value != "0" {
                d.add(&rules::SDP_VERSION, format!("v={} is not a supported version; use v=0", first.value))
                    .at(first.line);
            }
        }
        Some(first) => {
            d.add(&rules::SDP_VERSION, "the description must start with v=0").at(first.line);
        }
        None if sdp.media.is_empty() => {
            d.add(&rules::SDP_REQUIRED_LINE, "no SDP lines found");
            return;
        }
        None => {}
    }
    for (kind, what) in [('o', "origin (o=)"), ('s', "session name (s=)"), ('t', "timing (t=)")] {
        if session.field(kind).is_none() {
            d.add(&rules::SDP_REQUIRED_LINE, format!("the {what} line is missing"));
        }
    }
    for kind in ['v', 'o', 's', 'i', 'u', 'c', 'k'] {
        if let Some(extra) = session.fields_of(kind).nth(1) {
            d.add(&rules::SDP_DUPLICATE_LINE, format!("a second `{kind}=` line at session level")).at(extra.line);
        }
    }
    for media in &sdp.media {
        for kind in ['i', 'k'] {
            if let Some(extra) = media.fields_of(kind).nth(1) {
                d.add(&rules::SDP_DUPLICATE_LINE, format!("a second `{kind}=` line in one media section"))
                    .at(extra.line);
            }
        }
    }
    if let Some(origin) = session.field('o')
        && let Err(problem) = parse_origin(&origin.value)
    {
        d.add(&rules::SDP_ORIGIN, problem).at(origin.line);
    }
    if let Some(name) = session.field('s')
        && name.value.is_empty()
    {
        d.add(&rules::SDP_SESSION_NAME, "s= is empty; write s=- when there is no name").at(name.line);
    }
    for time in session.fields_of('t') {
        let parts: Vec<&str> = time.value.split_whitespace().collect();
        if parts.len() != 2 || parts.iter().any(|p| digits(p).is_none()) {
            d.add(&rules::SDP_TIMING, format!("t={} is not a start and stop time; use t=0 0", time.value))
                .at(time.line);
        }
    }
    let sections = std::iter::once(session).chain(&sdp.media);
    for field in sections.flat_map(|s| s.fields_of('b')) {
        if let Err(problem) = parse_bandwidth(&field.value) {
            d.add(&rules::SDP_BANDWIDTH, problem).at(field.line);
        }
    }
}

/// A parsed `o=` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// User name, often `-`.
    pub username: String,
    /// Session id, a numeric string.
    pub session_id: String,
    /// Session version, a numeric string that changes when the description changes.
    pub session_version: String,
    /// Network type, `IN`.
    pub net_type: String,
    /// Address type, `IP4` or `IP6`.
    pub addr_type: String,
    /// Address of the machine that created the description.
    pub address: String,
}

/// Parses the value of an `o=` line.
pub fn parse_origin(value: &str) -> Result<Origin, String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [username, session_id, session_version, net_type, addr_type, address] = parts[..] else {
        return Err(format!(
            "o= has {} fields; it needs six: username, session id, version, network type, address type, address",
            parts.len()
        ));
    };
    for (what, text) in [("session id", session_id), ("session version", session_version)] {
        if !text.bytes().all(|b| b.is_ascii_digit()) || text.is_empty() {
            return Err(format!("the {what} {text} is not a number"));
        }
    }
    Ok(Origin {
        username: username.into(),
        session_id: session_id.into(),
        session_version: session_version.into(),
        net_type: net_type.into(),
        addr_type: addr_type.to_string(),
        address: address.into(),
    })
}

/// A parsed `m=` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaLine {
    /// Media type: `video`, `audio`, `application`...
    pub media: String,
    /// Transport port.
    pub port: u16,
    /// Number of ports, when written as `port/count`.
    pub port_count: Option<u16>,
    /// Transport protocol, such as `RTP/AVP`.
    pub proto: String,
    /// Formats: RTP payload type numbers for RTP.
    pub formats: Vec<String>,
}

/// Parses the value of an `m=` line.
pub fn parse_media_line(value: &str) -> Result<MediaLine, String> {
    let mut parts = value.split_whitespace();
    let media = parts.next().ok_or("m= is empty")?;
    let port_text = parts.next().ok_or("m= has no port")?;
    let (port, port_count) = match port_text.split_once('/') {
        Some((port, count)) => (port, Some(count)),
        None => (port_text, None),
    };
    let number = |text: &str| {
        digits(text)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| format!("{text} is not a port number from 0 to 65535"))
    };
    let port = number(port)?;
    let port_count = port_count.map(number).transpose()?;
    let proto = parts.next().ok_or("m= has no protocol, such as RTP/AVP")?;
    let formats: Vec<String> = parts.map(String::from).collect();
    if formats.is_empty() {
        return Err("m= lists no format (payload type)".into());
    }
    Ok(MediaLine { media: media.into(), port, port_count, proto: proto.into(), formats })
}

/// A parsed `c=` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// Network type, `IN`.
    pub net_type: String,
    /// Address type, `IP4` or `IP6`.
    pub addr_type: String,
    /// The address as written, without TTL or count.
    pub address: String,
    /// The address as an IP address, when it is one rather than a host name.
    pub ip: Option<IpAddr>,
    /// TTL, for IPv4 multicast.
    pub ttl: Option<u8>,
    /// Number of consecutive addresses, when given.
    pub count: Option<u32>,
}

/// Parses the value of a `c=` line.
pub fn parse_connection(value: &str) -> Result<Connection, String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [net_type, addr_type, address] = parts[..] else {
        return Err(format!("c={value} needs three fields: IN, IP4 or IP6, and the address"));
    };
    if net_type != "IN" {
        return Err(format!("network type {net_type} is not IN"));
    }
    if addr_type != "IP4" && addr_type != "IP6" {
        return Err(format!("address type {addr_type} is not IP4 or IP6"));
    }
    let mut pieces = address.split('/');
    let base = pieces.next().unwrap_or_default();
    let suffixes: Vec<&str> = pieces.collect();
    let ip = base.parse::<IpAddr>().ok();
    match (addr_type, ip) {
        ("IP4", Some(IpAddr::V6(_))) | ("IP6", Some(IpAddr::V4(_))) => {
            return Err(format!("{base} does not match address type {addr_type}"));
        }
        _ => {}
    }
    if ip.is_none() && base.contains(|c: char| c == ':' || c.is_ascii_digit()) && !base.contains(char::is_alphabetic) {
        return Err(format!("{base} is not a valid address"));
    }
    let number = |text: &str| digits(text).ok_or_else(|| format!("{text} after `/` is not a number"));
    let (ttl, count) = if addr_type == "IP4" {
        let ttl = suffixes
            .first()
            .map(|t| number(t).and_then(|n| u8::try_from(n).map_err(|_| format!("TTL {n} is over 255"))))
            .transpose()?;
        let count = suffixes.get(1).map(|c| number(c)).transpose()?;
        (ttl, count)
    } else {
        (None, suffixes.first().map(|c| number(c)).transpose()?)
    };
    if suffixes.len() > if addr_type == "IP4" { 2 } else { 1 } {
        return Err(format!("{address} has too many `/` parts"));
    }
    let count = count.map(|c| u32::try_from(c).unwrap_or(u32::MAX));
    Ok(Connection { net_type: net_type.into(), addr_type: addr_type.to_string(), address: base.into(), ip, ttl, count })
}

/// Parses the value of a `b=` line into its type and value.
pub fn parse_bandwidth(value: &str) -> Result<(&str, u64), String> {
    let (kind, amount) = value.split_once(':').ok_or_else(|| format!("b={value} is not `<type>:<kbit/s>`"))?;
    if kind.is_empty() {
        return Err(format!("b={value} has no bandwidth type"));
    }
    let amount = digits(amount).ok_or_else(|| format!("bandwidth {amount} is not a whole number"))?;
    Ok((kind, amount))
}

/// A parsed `a=rtpmap` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpMap {
    /// RTP payload type.
    pub payload_type: u8,
    /// Encoding name, such as `raw` or `L24`.
    pub encoding: String,
    /// RTP clock rate in Hz.
    pub clock_rate: u32,
    /// Encoding parameters after the clock rate; the channel count for audio.
    pub params: Option<String>,
}

/// Parses the value of an `a=rtpmap` attribute.
pub fn parse_rtpmap(value: &str) -> Result<RtpMap, String> {
    let usage = "a=rtpmap is `<payload type> <encoding>/<clock rate>[/<channels>]`";
    let (pt, rest) = value.trim().split_once(char::is_whitespace).ok_or(usage)?;
    let payload_type = digits(pt)
        .and_then(|n| u8::try_from(n).ok())
        .filter(|n| *n <= 127)
        .ok_or_else(|| format!("{pt} is not an RTP payload type (0 to 127)"))?;
    let mut parts = rest.trim().splitn(3, '/');
    let encoding = parts.next().filter(|e| !e.is_empty()).ok_or(usage)?;
    let clock = parts.next().ok_or(usage)?;
    let clock_rate = digits(clock)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("clock rate {clock} is not a whole number of Hz"))?;
    Ok(RtpMap { payload_type, encoding: encoding.into(), clock_rate, params: parts.next().map(String::from) })
}

/// A parsed `a=source-filter` value (RFC 4570).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFilter {
    /// True for `incl`, false for `excl`.
    pub include: bool,
    /// Address type: `IP4`, `IP6` or `*`.
    pub addr_type: String,
    /// Destination address, or `*` for every destination.
    pub destination: String,
    /// Source addresses.
    pub sources: Vec<String>,
}

/// Parses the value of an `a=source-filter` attribute.
pub fn parse_source_filter(value: &str) -> Result<SourceFilter, String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [mode, net_type, addr_type, destination, sources @ ..] = parts.as_slice() else {
        return Err("a=source-filter needs incl or excl, IN, the address type, the destination and a source".into());
    };
    let include = match *mode {
        "incl" => true,
        "excl" => false,
        other => return Err(format!("filter mode {other} is not incl or excl")),
    };
    if *net_type != "IN" && *net_type != "*" {
        return Err(format!("network type {net_type} is not IN"));
    }
    if !matches!(*addr_type, "IP4" | "IP6" | "*") {
        return Err(format!("address type {addr_type} is not IP4, IP6 or *"));
    }
    if sources.is_empty() {
        return Err("a=source-filter names no source address".into());
    }
    Ok(SourceFilter {
        include,
        addr_type: addr_type.to_string(),
        destination: destination.to_string(),
        sources: sources.iter().map(|s| s.to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_ids(text: &str) -> Vec<&'static str> {
        parse(text).1.iter().map(|d| d.rule).collect()
    }

    #[test]
    fn splits_session_and_media() {
        let (sdp, diagnostics) =
            parse("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 5004 RTP/AVP 97\r\na=ptime:1\r\n");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(sdp.session.fields.len(), 4);
        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].attribute("ptime").unwrap().value, Some("1"));
        assert_eq!(sdp.media[0].fields[1].line, 6);
    }

    #[test]
    fn syntax_problems() {
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\na = x\n"), ["sdp-syntax"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\n\na=x\n"), ["sdp-blank-line"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\nx=1\n"), ["sdp-unknown-type"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\nA=1\n"), ["sdp-syntax"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns= \nt=0 0\n"), Vec::<&str>::new());
    }

    #[test]
    fn order_problems() {
        // An attribute before t= is the usual slip.
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\na=group:DUP a b\nt=0 0\n"), ["sdp-order"]);
        assert_eq!(
            rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\nm=video 5004 RTP/AVP 96\na=x\nc=IN IP4 10.0.0.2\n"),
            ["sdp-order"]
        );
    }

    #[test]
    fn required_and_duplicate_lines() {
        assert_eq!(rule_ids("v=0\ns=-\n"), ["sdp-required-line", "sdp-required-line"]);
        assert_eq!(rule_ids("v=1\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=0 0\n"), ["sdp-version"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\ns=again\nt=0 0\n"), ["sdp-duplicate-line"]);
        assert_eq!(rule_ids(""), ["sdp-required-line"]);
    }

    #[test]
    fn origin_and_timing() {
        assert_eq!(rule_ids("v=0\no=- 1 IN IP4 10.0.0.1\ns=-\nt=0 0\n"), ["sdp-origin"]);
        assert_eq!(rule_ids("v=0\no=- abc 1 IN IP4 10.0.0.1\ns=-\nt=0 0\n"), ["sdp-origin"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=\nt=0 0\n"), ["sdp-session-name"]);
        assert_eq!(rule_ids("v=0\no=- 1 1 IN IP4 10.0.0.1\ns=-\nt=now\n"), ["sdp-timing"]);
    }

    #[test]
    fn connections() {
        let c = parse_connection("IN IP4 239.10.10.1/32").unwrap();
        assert_eq!((c.address.as_str(), c.ttl, c.count), ("239.10.10.1", Some(32), None));
        let c = parse_connection("IN IP4 239.10.10.1/32/4").unwrap();
        assert_eq!(c.count, Some(4));
        let c = parse_connection("IN IP6 ff3e::1/2").unwrap();
        assert_eq!((c.ttl, c.count), (None, Some(2)));
        assert!(parse_connection("IN IP4 ff3e::1").is_err());
        assert!(parse_connection("IN IP4 239.10.10.1/300").is_err());
        assert!(parse_connection("IN IP4 239.10.300.1").is_err());
        assert!(parse_connection("IN IP4").is_err());
        assert!(parse_connection("IN IP4 camera.example.net").unwrap().ip.is_none());
    }

    #[test]
    fn media_lines_and_rtpmaps() {
        let m = parse_media_line("video 5004 RTP/AVP 96").unwrap();
        assert_eq!((m.port, m.proto.as_str(), m.formats.len()), (5004, "RTP/AVP", 1));
        assert!(parse_media_line("video 70000 RTP/AVP 96").is_err());
        assert!(parse_media_line("video 5004 RTP/AVP").is_err());
        let r = parse_rtpmap("97 L24/48000/8").unwrap();
        assert_eq!((r.payload_type, r.encoding.as_str(), r.clock_rate), (97, "L24", 48000));
        assert_eq!(r.params.as_deref(), Some("8"));
        assert!(parse_rtpmap("200 raw/90000").is_err());
        assert!(parse_rtpmap("96 raw").is_err());
        assert!(parse_rtpmap("96 raw/fast").is_err());
    }

    #[test]
    fn source_filters() {
        let f = parse_source_filter(" incl IN IP4 239.10.10.1 192.168.10.21").unwrap();
        assert!(f.include);
        assert_eq!(f.sources, ["192.168.10.21"]);
        assert!(parse_source_filter("incl IN IP4 239.10.10.1").is_err());
        assert!(parse_source_filter("include IN IP4 239.10.10.1 10.0.0.1").is_err());
    }
}
