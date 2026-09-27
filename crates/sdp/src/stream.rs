//! Streams: one per media section, classified by the part of ST 2110 they follow.

use std::net::IpAddr;

use crate::clock::{MediaClock, RefClock};
use crate::diag::Diagnostics;
use crate::fmtp::{Fmtp, Param};
use crate::rational::digits;
use crate::rules;
use crate::sdp::{
    Attribute, Connection, MediaLine, RtpMap, Section, SessionDescription, parse_connection, parse_media_line,
    parse_rtpmap, parse_source_filter,
};

/// Which part of the ST 2110 suite a stream follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Essence {
    /// Uncompressed video, ST 2110-20 (`raw`).
    Video,
    /// Constant bit-rate compressed video, ST 2110-22 (such as `jxsv`).
    CompressedVideo,
    /// PCM audio, ST 2110-30 (`L16`, `L24`).
    Audio,
    /// AES3 transparent transport, ST 2110-31 (`AM824`).
    Aes3,
    /// SMPTE ST 291-1 ancillary data, ST 2110-40 (`smpte291`).
    Ancillary,
    /// Fast metadata, ST 2110-41 (`ST2110-41`).
    FastMetadata,
    /// Timed text, ST 2110-43 (`ttml+xml`).
    TimedText,
    /// SDI over IP, ST 2022-6 timed by ST 2022-8 (`SMPTE2022-6`).
    Sdi,
    /// Anything else.
    Unknown,
}

impl Essence {
    /// The standard that defines the stream, such as `ST 2110-20`.
    pub fn standard(self) -> &'static str {
        match self {
            Self::Video => "ST 2110-20",
            Self::CompressedVideo => "ST 2110-22",
            Self::Audio => "ST 2110-30",
            Self::Aes3 => "ST 2110-31",
            Self::Ancillary => "ST 2110-40",
            Self::FastMetadata => "ST 2110-41",
            Self::TimedText => "ST 2110-43",
            Self::Sdi => "ST 2022-6",
            Self::Unknown => "not ST 2110",
        }
    }

    /// Classifies a media section by media type and `a=rtpmap` encoding name.
    pub fn classify(media: &str, encoding: &str) -> Self {
        let encoding = encoding.to_ascii_lowercase();
        match (media.to_ascii_lowercase().as_str(), encoding.as_str()) {
            (_, "smpte291") => Self::Ancillary,
            (_, "st2110-41") => Self::FastMetadata,
            (_, "ttml+xml") => Self::TimedText,
            ("video", "raw") => Self::Video,
            ("video", "smpte2022-6") => Self::Sdi,
            ("video", _) => Self::CompressedVideo,
            ("audio", "l16" | "l24") => Self::Audio,
            ("audio", "am824") => Self::Aes3,
            _ => Self::Unknown,
        }
    }
}

/// What the linter learned about one media section.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Stream {
    /// Position among the media sections, counting from 0.
    pub index: usize,
    /// Line of the `m=` line.
    pub line: usize,
    /// Media type from the `m=` line.
    pub media: String,
    /// Which part of ST 2110 the stream follows.
    pub essence: Essence,
    /// The `a=mid` identifier, which groups such as ST 2022-7 `DUP` refer to.
    pub mid: Option<String>,
    /// Destination address from `c=`.
    pub destination: Option<String>,
    /// Destination port from `m=`.
    pub port: Option<u16>,
    /// Sender address from the `a=source-filter` that matches the destination.
    pub source: Option<String>,
    /// RTP payload type.
    pub payload_type: Option<u8>,
    /// Encoding name from `a=rtpmap`.
    pub encoding: Option<String>,
    /// RTP clock rate in Hz.
    pub clock_rate: Option<u32>,
    /// Audio channel count from `a=rtpmap`.
    pub channels: Option<u16>,
    /// The reference clock, from `a=ts-refclk`.
    pub reference_clock: Option<RefClock>,
    /// The media clock, from `a=mediaclk`.
    pub media_clock: Option<MediaClock>,
    /// Format parameters from `a=fmtp`.
    pub parameters: Vec<Param>,
    /// A one-line description of the format.
    pub summary: String,
    /// Bits per second of essence payload (pixels or samples) before any headers,
    /// where the SDP fixes it exactly.
    pub payload_bitrate: Option<f64>,
}

/// One media section with the attributes the checks need, already parsed.
pub(crate) struct Media<'a> {
    pub index: usize,
    /// Line of the `m=` line.
    pub line: usize,
    pub section: &'a Section,
    pub session: &'a Section,
    pub mline: Option<MediaLine>,
    /// The first format on the `m=` line, when it is a number.
    pub payload_type: Option<u8>,
    pub rtpmap: Option<(usize, RtpMap)>,
    pub fmtp: Option<(usize, Fmtp)>,
    /// The effective connection: this section's, or else the session's.
    pub connection: Option<(usize, Connection)>,
    pub essence: Essence,
    pub mid: Option<String>,
}

impl<'a> Media<'a> {
    /// Attributes with this name in the media section or, if there are none, at
    /// session level. The flag is true when they come from the session level.
    pub fn attrs(&self, name: &'a str) -> (Vec<Attribute<'a>>, bool) {
        let here: Vec<_> = self.section.attributes_named(name).collect();
        if !here.is_empty() {
            return (here, false);
        }
        (self.session.attributes_named(name).collect(), true)
    }

    /// Format parameters and the line they are on.
    pub fn format(&self) -> Option<(usize, &Fmtp)> {
        self.fmtp.as_ref().map(|(line, fmtp)| (*line, fmtp))
    }

    /// A format parameter's value.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.fmtp.as_ref()?.1.value(name)
    }

    /// The signalled `MAXUDP`, when it is a number.
    pub fn maxudp(&self) -> Option<u32> {
        digits(self.value("MAXUDP")?).and_then(|n| u32::try_from(n).ok())
    }

    /// The effective reference clock, if it parses.
    pub fn reference_clock(&self) -> Option<RefClock> {
        let (attrs, _) = self.attrs("ts-refclk");
        attrs.iter().find_map(|a| RefClock::parse(a.text()).ok())
    }

    /// The source address from the `incl` filter that matches the destination.
    pub fn source(&self) -> Option<String> {
        let (_, connection) = self.connection.as_ref()?;
        let (filters, _) = self.attrs("source-filter");
        filters
            .iter()
            .filter_map(|a| parse_source_filter(a.text()).ok())
            .find(|f| f.include && (f.destination == "*" || same_address(&f.destination, &connection.address)))
            .and_then(|f| f.sources.into_iter().next())
    }
}

/// Compares two addresses as IP addresses when both are, and as text otherwise.
pub(crate) fn same_address(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// Builds a view of every media section, reporting malformed lines as it goes.
pub(crate) fn build<'a>(sdp: &'a SessionDescription, d: &mut Diagnostics) -> Vec<Media<'a>> {
    let session_connection = sdp.session.field('c').and_then(|field| match parse_connection(&field.value) {
        Ok(connection) => Some((field.line, connection)),
        Err(problem) => {
            d.add(&rules::SDP_CONNECTION, problem).at(field.line);
            None
        }
    });
    let mut all = Vec::with_capacity(sdp.media.len());
    for (index, section) in sdp.media.iter().enumerate() {
        let first = &section.fields[0];
        let line = first.line;
        let mline = match parse_media_line(&first.value) {
            Ok(mline) => Some(mline),
            Err(problem) => {
                d.report(&rules::SDP_MEDIA_LINE, index, line, problem);
                None
            }
        };
        let formats: Vec<&str> = mline.iter().flat_map(|m| m.formats.iter().map(String::as_str)).collect();
        let payload_type = formats.first().and_then(|f| digits(f)).and_then(|n| u8::try_from(n).ok());

        let mut connection = None;
        let mut bad_connection = false;
        for field in section.fields_of('c') {
            match parse_connection(&field.value) {
                Ok(parsed) => {
                    connection.get_or_insert((field.line, parsed));
                }
                Err(problem) => {
                    bad_connection = true;
                    d.report(&rules::SDP_CONNECTION, index, field.line, problem);
                }
            }
        }
        let connection = connection.or_else(|| session_connection.clone());
        if connection.is_none() && !bad_connection && sdp.session.field('c').is_none() {
            d.report(
                &rules::SDP_CONNECTION,
                index,
                line,
                "no connection address: add a c= line here or at session level",
            );
        }
        if let Some((cline, c)) = &connection {
            check_ttl(c, *cline, index, d);
        }

        let rtpmap = rtpmaps(section, index, &formats, payload_type, d);
        if rtpmap.is_none() && payload_type.is_some_and(|pt| pt >= 96) {
            d.report(&rules::RTPMAP_MISSING, index, line, format!("payload type {} has no a=rtpmap line", formats[0]));
        }
        let fmtp = fmtps(section, index, &formats, payload_type, d);

        let mids: Vec<Attribute<'_>> = section.attributes_named("mid").collect();
        if let Some(extra) = mids.get(1) {
            d.report(&rules::SDP_DUPLICATE_ATTRIBUTE, index, extra.line, "a second a=mid line in one media section");
        }
        let mid = mids.first().map(|a| a.text().to_string()).filter(|m| !m.is_empty());

        let essence = match (&mline, &rtpmap) {
            (Some(m), Some((_, map))) => Essence::classify(&m.media, &map.encoding),
            _ => Essence::Unknown,
        };
        all.push(Media {
            index,
            line,
            section,
            session: &sdp.session,
            mline,
            payload_type,
            rtpmap,
            fmtp,
            connection,
            essence,
            mid,
        });
    }
    all
}

fn check_ttl(c: &Connection, line: usize, index: usize, d: &mut Diagnostics) {
    let Some(ip) = c.ip else { return };
    match (ip.is_multicast(), c.addr_type.as_str(), c.ttl) {
        (true, "IP4", None) => {
            d.report(
                &rules::SDP_MULTICAST_TTL,
                index,
                line,
                format!("IPv4 multicast address {ip} has no TTL; write {ip}/32 or similar"),
            );
        }
        (false, "IP4", Some(ttl)) => {
            d.report(
                &rules::SDP_MULTICAST_TTL,
                index,
                line,
                format!("unicast address {ip} carries /{ttl}; a TTL is only for multicast"),
            );
        }
        _ => {}
    }
}

fn rtpmaps(
    section: &Section,
    index: usize,
    formats: &[&str],
    payload_type: Option<u8>,
    d: &mut Diagnostics,
) -> Option<(usize, RtpMap)> {
    let mut chosen = None;
    let mut seen = Vec::new();
    for attr in section.attributes_named("rtpmap") {
        match parse_rtpmap(attr.text()) {
            Ok(map) => {
                let pt = map.payload_type;
                if seen.contains(&pt) {
                    d.report(
                        &rules::SDP_DUPLICATE_ATTRIBUTE,
                        index,
                        attr.line,
                        format!("payload type {pt} has a second a=rtpmap line"),
                    );
                    continue;
                }
                seen.push(pt);
                if !formats.contains(&pt.to_string().as_str()) {
                    d.report(
                        &rules::FORMAT_UNLISTED,
                        index,
                        attr.line,
                        format!("a=rtpmap describes payload type {pt}, which the m= line does not list"),
                    );
                }
                if Some(pt) == payload_type {
                    chosen = Some((attr.line, map));
                }
            }
            Err(problem) => {
                d.report(&rules::RTPMAP_SYNTAX, index, attr.line, problem);
            }
        }
    }
    chosen
}

fn fmtps(
    section: &Section,
    index: usize,
    formats: &[&str],
    payload_type: Option<u8>,
    d: &mut Diagnostics,
) -> Option<(usize, Fmtp)> {
    let mut chosen = None;
    let mut seen = Vec::new();
    for attr in section.attributes_named("fmtp") {
        let text = attr.text();
        let (pt, params) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
        if !formats.contains(&pt) {
            d.report(
                &rules::FORMAT_UNLISTED,
                index,
                attr.line,
                format!("a=fmtp is for payload type {pt}, which the m= line does not list"),
            );
        }
        if seen.contains(&pt) {
            d.report(
                &rules::SDP_DUPLICATE_ATTRIBUTE,
                index,
                attr.line,
                format!("payload type {pt} has a second a=fmtp line"),
            );
            continue;
        }
        seen.push(pt);
        let (fmtp, problems) = Fmtp::parse(params);
        for problem in problems {
            d.report(&rules::FMTP_SYNTAX, index, attr.line, problem);
        }
        if payload_type.is_some_and(|p| p.to_string() == pt) {
            chosen = Some((attr.line, fmtp));
        }
    }
    chosen
}

/// The public summary of one stream.
pub(crate) fn summarize(m: &Media<'_>) -> Stream {
    let (summary, payload_bitrate) = crate::lint::describe(m);
    let (media_clocks, _) = m.attrs("mediaclk");
    Stream {
        index: m.index,
        line: m.line,
        media: m.mline.as_ref().map(|l| l.media.clone()).unwrap_or_default(),
        essence: m.essence,
        mid: m.mid.clone(),
        destination: m.connection.as_ref().map(|(_, c)| c.address.clone()),
        port: m.mline.as_ref().map(|l| l.port),
        source: m.source(),
        payload_type: m.payload_type,
        encoding: m.rtpmap.as_ref().map(|(_, r)| r.encoding.clone()),
        clock_rate: m.rtpmap.as_ref().map(|(_, r)| r.clock_rate),
        channels: match m.essence {
            Essence::Audio | Essence::Aes3 => {
                m.rtpmap.as_ref().and_then(|(_, r)| r.params.as_deref().map_or(Some(1), |p| p.parse().ok()))
            }
            _ => None,
        },
        reference_clock: m.reference_clock(),
        media_clock: media_clocks.iter().find_map(|a| MediaClock::parse(a.text()).ok()),
        parameters: m.fmtp.as_ref().map(|(_, f)| f.params.clone()).unwrap_or_default(),
        summary,
        payload_bitrate,
    }
}

#[cfg(test)]
mod tests {
    use super::Essence;

    #[test]
    fn classify() {
        assert_eq!(Essence::classify("video", "raw"), Essence::Video);
        assert_eq!(Essence::classify("video", "jxsv"), Essence::CompressedVideo);
        assert_eq!(Essence::classify("video", "smpte291"), Essence::Ancillary);
        assert_eq!(Essence::classify("video", "SMPTE2022-6"), Essence::Sdi);
        assert_eq!(Essence::classify("audio", "L24"), Essence::Audio);
        assert_eq!(Essence::classify("audio", "AM824"), Essence::Aes3);
        assert_eq!(Essence::classify("application", "ST2110-41"), Essence::FastMetadata);
        assert_eq!(Essence::classify("application", "ttml+xml"), Essence::TimedText);
        assert_eq!(Essence::classify("audio", "opus"), Essence::Unknown);
        assert_eq!(Essence::classify("application", "raw"), Essence::Unknown);
    }
}
