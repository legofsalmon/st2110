//! The RTP streams an SDP file describes, as IS-05 maps them onto a Receiver's
//! transport parameters.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use st2110_sdp::{Section, SessionDescription, parse_connection, parse_media_line, parse_source_filter};

/// One RTP stream a Receiver joins: the only one, or one leg of an ST 2022-7 pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leg {
    /// Where the stream goes: a multicast group, or for unicast the Receiver's own address.
    pub destination: String,
    /// Whether `destination` is a multicast group.
    pub multicast: bool,
    /// The Sender's address, from `a=source-filter`, for source-specific multicast.
    pub source_ip: Option<String>,
    /// The UDP port the stream goes to.
    pub destination_port: u16,
}

impl Leg {
    /// `239.10.10.1:5004 from 192.168.10.21`, or `239.10.10.1:5004 from any source`.
    pub fn describe(&self) -> String {
        let from = match &self.source_ip {
            Some(source) => format!("from {source}"),
            None if self.multicast => "from any source".into(),
            None => "unicast".into(),
        };
        let at = match self.destination.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{}]:{}", self.destination, self.destination_port),
            _ => format!("{}:{}", self.destination, self.destination_port),
        };
        format!("{at} {from}")
    }
}

/// The streams an SDP file describes, with anything a controller should tell its operator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Legs {
    /// The legs, path 1 first.
    pub legs: Vec<Leg>,
    /// Media sections that are left out, and why.
    pub notes: Vec<String>,
}

/// Reads the RTP streams in an SDP file as IS-05 v1.2 maps them onto a Receiver's
/// transport parameters (Behaviour: RTP Transport Type):
///
/// - the media sections that the session's `a=group:DUP` names are the legs of an
///   ST 2022-7 pair, in the order they appear in the file (RFC 7104 §4.2);
/// - otherwise the first media section is the stream, and two legs of a pair when its
///   `a=ssrc-group:DUP` names two SSRCs (RFC 7104 §4.1): from the two sources its
///   `a=source-filter` lists, or twice from the one;
/// - its `c=` line gives the multicast group or unicast address, its `m=` line the port,
///   and an `incl` `a=source-filter` for that address the source (RFC 4570).
///
/// Fails when the file has no usable media section, or one that is off, not RTP, or has
/// no IP address.
pub fn legs(sdp: &str) -> Result<Legs, String> {
    let (sdp, _) = st2110_sdp::parse(sdp);
    if sdp.media.is_empty() {
        return Err("the SDP file has no media section".into());
    }
    let mut notes = Vec::new();
    let group: Option<Vec<&str>> = sdp.session.attributes_named("group").find_map(|a| {
        let mut words = a.text().split_whitespace();
        words.next().filter(|semantics| semantics.eq_ignore_ascii_case("DUP"))?;
        Some(words.collect())
    });
    let mids: Vec<Option<&str>> =
        sdp.media.iter().map(|m| m.attribute("mid").and_then(|a| a.value).map(str::trim)).collect();
    let sections: Vec<usize> = match &group {
        Some(group) => {
            let named: Vec<usize> =
                (0..sdp.media.len()).filter(|&i| mids[i].is_some_and(|mid| group.contains(&mid))).collect();
            if named.len() < 2 {
                let (sections, carry) = if named.len() == 1 { ("section", "carries") } else { ("sections", "carry") };
                return Err(format!(
                    "a=group:DUP names {}, but {} media {sections} {carry} one of those a=mid values",
                    group.join(" "),
                    named.len()
                ));
            }
            named
        }
        None => vec![0],
    };
    let left_out: Vec<String> = (0..sdp.media.len()).filter(|i| !sections.contains(i)).map(|i| i.to_string()).collect();
    if !left_out.is_empty() {
        let (sections, verb, them) =
            if left_out.len() == 1 { ("section", "is", "it") } else { ("sections", "are", "them") };
        let why = if group.is_some() {
            format!("a=group:DUP does not name {them}")
        } else {
            "without a=group:DUP only the first is received".into()
        };
        notes.push(format!("media {sections} {} {verb} left out: {why}", left_out.join(", ")));
    }

    let mut legs = Vec::new();
    for &index in &sections {
        let section = &sdp.media[index];
        let (leg, sources) = leg(&sdp, section, index)?;
        let dup_ssrcs = section.attributes_named("ssrc-group").find_map(|a| {
            let mut words = a.text().split_whitespace();
            words.next().filter(|semantics| semantics.eq_ignore_ascii_case("DUP")).map(|_| words.count())
        });
        match dup_ssrcs {
            // Both legs of a pair in one media section.
            Some(ssrcs) if group.is_none() && ssrcs >= 2 => {
                let second = sources.get(1).cloned().or_else(|| leg.source_ip.clone());
                legs.push(leg.clone());
                legs.push(Leg { source_ip: second, ..leg });
            }
            _ => legs.push(leg),
        }
    }
    Ok(Legs { legs, notes })
}

/// One media section's stream, and every source its `a=source-filter` lists.
fn leg(sdp: &SessionDescription, section: &Section, index: usize) -> Result<(Leg, Vec<String>), String> {
    let mline = parse_media_line(&section.fields[0].value).map_err(|e| format!("media section {index}: {e}"))?;
    if mline.port == 0 {
        return Err(format!("media section {index} has port 0, which turns it off"));
    }
    if !mline.proto.to_ascii_uppercase().starts_with("RTP/") {
        return Err(format!("media section {index} is carried over {}, not RTP", mline.proto));
    }
    let field = section
        .field('c')
        .or_else(|| sdp.session.field('c'))
        .ok_or_else(|| format!("media section {index} has no c= line"))?;
    let connection = parse_connection(&field.value).map_err(|e| format!("media section {index}: {e}"))?;
    let ip = connection
        .ip
        .ok_or_else(|| format!("media section {index} goes to {}, which is not an IP address", connection.address))?;
    let mut filters: Vec<_> = section.attributes_named("source-filter").collect();
    if filters.is_empty() {
        filters = sdp.session.attributes_named("source-filter").collect();
    }
    let sources = filters
        .iter()
        .filter_map(|a| parse_source_filter(a.text()).ok())
        .find(|f| f.include && (f.destination == "*" || f.destination.parse::<IpAddr>().ok() == Some(ip)))
        .map(|f| f.sources)
        .unwrap_or_default();
    let leg = Leg {
        destination: ip.to_string(),
        multicast: ip.is_multicast(),
        source_ip: sources.first().cloned(),
        destination_port: mline.port,
    };
    Ok((leg, sources))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leg of a stream from 198.51.100.1 to 233.252.0.1, port 30000.
    fn leg(destination: &str, source: Option<&str>) -> Leg {
        Leg {
            destination: destination.into(),
            multicast: destination.parse::<IpAddr>().unwrap().is_multicast(),
            source_ip: source.map(str::to_string),
            destination_port: 30000,
        }
    }

    fn read(sdp: &str) -> Vec<Leg> {
        legs(&sdp.replace('\n', "\r\n")).expect("usable").legs
    }

    // The examples in IS-05 v1.2 Behaviour: RTP Transport Type, and the transport
    // parameters it says a Receiver shows for each.

    #[test]
    fn unicast() {
        let legs = read(
            "v=0\no=- 2890844526 2890842807 IN IP4 10.47.16.5\ns=SDP Example\nc=IN IP4 10.46.16.34/127\n\
             t=2873397496 2873404696\na=recvonly\nm=video 51372 RTP/AVP 99\na=rtpmap:99 h263-1998/90000\n",
        );
        assert_eq!(
            legs,
            [Leg { destination: "10.46.16.34".into(), multicast: false, source_ip: None, destination_port: 51372 }]
        );
        assert_eq!(legs[0].describe(), "10.46.16.34:51372 unicast");
    }

    #[test]
    fn source_specific_and_any_source_multicast() {
        let ssm = read(
            "v=0\no=- 1497010742 1497010742 IN IP4 172.29.26.24\ns=SDP Example\nt=2873397496 2873404696\n\
             m=video 5000 RTP/AVP 103\nc=IN IP4 232.21.21.133/32\n\
             a=source-filter: incl IN IP4 232.21.21.133 172.29.226.24\na=rtpmap:103 raw/90000\n",
        );
        assert_eq!(ssm[0].describe(), "232.21.21.133:5000 from 172.29.226.24");
        let asm = read(
            "v=0\no=- 1497010742 1497010742 IN IP4 172.29.26.24\ns=SDP Example\nt=2873397496 2873404696\n\
             m=video 5000 RTP/AVP 103\nc=IN IP4 239.21.21.133/32\na=rtpmap:103 raw/90000\n",
        );
        assert_eq!(asm[0].describe(), "239.21.21.133:5000 from any source");
    }

    #[test]
    fn st_2022_7_separate_source_addresses() {
        let legs = read(
            "v=0\no=ali 1122334455 1122334466 IN IP4 dup.example.com\ns=DUP Grouping Semantics\nt=0 0\n\
             m=video 30000 RTP/AVP 100\nc=IN IP4 233.252.0.1/127\n\
             a=source-filter: incl IN IP4 233.252.0.1 198.51.100.1 198.51.100.2\na=rtpmap:100 MP2T/90000\n\
             a=ssrc:1000 cname:ch1@example.com\na=ssrc:1010 cname:ch1@example.com\na=ssrc-group:DUP 1000 1010\n\
             a=mid:Ch1\n",
        );
        assert_eq!(legs, [leg("233.252.0.1", Some("198.51.100.1")), leg("233.252.0.1", Some("198.51.100.2"))]);
    }

    #[test]
    fn st_2022_7_separate_destination_addresses() {
        let legs = read(
            "v=0\no=ali 1122334455 1122334466 IN IP4 dup.example.com\ns=DUP Grouping Semantics\nt=0 0\n\
             a=group:DUP S1a S1b\nm=video 30000 RTP/AVP 100\nc=IN IP4 233.252.0.1/127\n\
             a=source-filter: incl IN IP4 233.252.0.1 198.51.100.1\na=rtpmap:100 MP2T/90000\na=mid:S1a\n\
             m=video 30000 RTP/AVP 101\nc=IN IP4 233.252.0.2/127\n\
             a=source-filter: incl IN IP4 233.252.0.2 198.51.100.1\na=rtpmap:101 MP2T/90000\na=mid:S1b\n",
        );
        assert_eq!(legs, [leg("233.252.0.1", Some("198.51.100.1")), leg("233.252.0.2", Some("198.51.100.1"))]);
    }

    #[test]
    fn st_2022_7_temporal_redundancy() {
        let legs = read(
            "v=0\no=ali 1122334455 1122334466 IN IP4 dup.example.com\ns=Delayed Duplication\nt=0 0\n\
             m=video 30000 RTP/AVP 100\nc=IN IP4 233.252.0.1/127\n\
             a=source-filter: incl IN IP4 233.252.0.1 198.51.100.1\na=rtpmap:100 MP2T/90000\n\
             a=ssrc:1000 cname:ch1a@example.com\na=ssrc:1010 cname:ch1a@example.com\n\
             a=ssrc-group:DUP 1000 1010\na=duplication-delay:50\na=mid:Ch1\n",
        );
        assert_eq!(legs, [leg("233.252.0.1", Some("198.51.100.1")), leg("233.252.0.1", Some("198.51.100.1"))]);
    }

    #[test]
    fn media_sections_outside_the_stream_are_noted() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=x\r\nt=0 0\r\nm=video 5004 RTP/AVP 96\r\n\
                   c=IN IP4 239.1.1.1/32\r\nm=audio 5006 RTP/AVP 97\r\nc=IN IP4 239.1.1.2/32\r\n";
        let read = legs(sdp).unwrap();
        assert_eq!(read.legs.len(), 1);
        assert_eq!(read.notes, ["media section 1 is left out: without a=group:DUP only the first is received"]);
        // IPv6, with a session-level connection and source filter.
        let v6 = "v=0\r\no=- 1 1 IN IP6 ::1\r\ns=x\r\nc=IN IP6 ff3e::8000:1\r\n\
                  a=source-filter: incl IN IP6 * 2001:db8::1\r\nt=0 0\r\nm=video 5004 RTP/AVP 96\r\n";
        assert_eq!(legs(v6).unwrap().legs[0].describe(), "[ff3e::8000:1]:5004 from 2001:db8::1");
    }

    #[test]
    fn unusable_files_say_why() {
        let error = |sdp: &str| legs(sdp).unwrap_err();
        assert_eq!(error("v=0\r\n"), "the SDP file has no media section");
        let base = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=x\r\nt=0 0\r\n";
        assert_eq!(error(&format!("{base}m=video 0 RTP/AVP 96\r\n")), "media section 0 has port 0, which turns it off");
        assert_eq!(error(&format!("{base}m=video 5004 RTP/AVP 96\r\n")), "media section 0 has no c= line");
        assert_eq!(
            error(&format!("{base}m=video 5004 udp 96\r\nc=IN IP4 239.1.1.1/32\r\n")),
            "media section 0 is carried over udp, not RTP"
        );
        assert_eq!(
            error(&format!("{base}m=video 5004 RTP/AVP 96\r\nc=IN IP4 mcast.example/32\r\n")),
            "media section 0 goes to mcast.example, which is not an IP address"
        );
        assert_eq!(
            error(&format!("{base}a=group:DUP p s\r\nm=video 5004 RTP/AVP 96\r\nc=IN IP4 239.1.1.1/32\r\na=mid:p\r\n")),
            "a=group:DUP names p s, but 1 media section carries one of those a=mid values"
        );
    }
}
