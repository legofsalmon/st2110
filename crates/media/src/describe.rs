//! Stream descriptions: the SDP file a sender writes, and the one a receiver reads.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use st2110_sdp::{ClockIdentity, Fmtp, RefClock, Section, parse_connection, parse_media_line, parse_rtpmap};

use crate::format::{AudioFormat, VideoFormat, samples_in};

/// What a stream carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Media {
    /// ST 2110-20 video.
    Video(VideoFormat),
    /// ST 2110-30 PCM audio.
    Audio(AudioFormat),
}

impl Media {
    /// The RTP clock rate: 90 kHz for video, the sampling rate for audio.
    pub fn clock_rate(&self) -> u32 {
        match self {
            Self::Video(_) => 90_000,
            Self::Audio(a) => a.sample_rate,
        }
    }

    /// Says why the format cannot be sent or received, if it cannot.
    pub fn check(&self) -> Result<(), String> {
        match self {
            Self::Video(v) => v.check(),
            Self::Audio(a) => a.check(),
        }
    }
}

impl fmt::Display for Media {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Video(v) => v.fmt(f),
            Self::Audio(a) => a.fmt(f),
        }
    }
}

/// One leg of a stream: where its packets go, and where they come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    /// The multicast group, or the receiver's own address for unicast, and the port.
    pub destination: SocketAddrV4,
    /// The sender's address, which an `a=source-filter` names for source-specific
    /// multicast; `None` for any source.
    pub source: Option<Ipv4Addr>,
}

impl fmt::Display for Leg {
    /// `239.1.1.1:5004 from 192.168.1.10`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source {
            Some(source) => write!(f, "{} from {source}", self.destination),
            None if self.destination.ip().is_multicast() => write!(f, "{} from any source", self.destination),
            None => write!(f, "{} unicast", self.destination),
        }
    }
}

/// The clock a stream's RTP timestamps count, as `a=ts-refclk` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clock {
    /// PTP from one grandmaster: `ptp=IEEE1588-2008:<grandmaster>:<domain>`.
    Ptp {
        /// The grandmaster's clock identity.
        grandmaster: ClockIdentity,
        /// The PTP domain, when given.
        domain: Option<u8>,
    },
    /// PTP traceable to TAI, from any grandmaster: `ptp=IEEE1588-2008:traceable`.
    Traceable,
    /// No PTP: the sender's own clock, named by one of its MAC addresses: `localmac=`.
    LocalMac(String),
}

impl Clock {
    /// Reads `traceable`, `<grandmaster>:<domain>` such as `08-00-11-FF-FE-21-E1-B0:127`,
    /// `localmac=<MAC>`, or a whole `ts-refclk` value.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let value = if text.eq_ignore_ascii_case("traceable") {
            "ptp=IEEE1588-2008:traceable".to_string()
        } else if text.contains('=') {
            text.to_string()
        } else {
            format!("ptp=IEEE1588-2008:{text}")
        };
        match RefClock::parse(&value)? {
            RefClock::Ptp { traceable: true, .. } => Ok(Self::Traceable),
            RefClock::Ptp { grandmaster: Some(grandmaster), domain, .. } => Ok(Self::Ptp { grandmaster, domain }),
            RefClock::LocalMac { address } => Ok(Self::LocalMac(address)),
            _ => Err(format!(
                "{text} is not a reference clock: give traceable, <grandmaster>:<domain> or localmac=<MAC address>"
            )),
        }
    }

    /// The `a=ts-refclk` value.
    pub fn sdp_value(&self) -> String {
        match self {
            Self::Ptp { grandmaster, domain: Some(domain) } => format!("ptp=IEEE1588-2008:{grandmaster}:{domain}"),
            Self::Ptp { grandmaster, domain: None } => format!("ptp=IEEE1588-2008:{grandmaster}"),
            Self::Traceable => "ptp=IEEE1588-2008:traceable".into(),
            Self::LocalMac(address) => format!("localmac={address}"),
        }
    }
}

/// A stream as an SDP file describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    /// The session name, `s=`.
    pub name: String,
    /// What it carries.
    pub media: Media,
    /// The RTP payload type, 96 to 127.
    pub payload_type: u8,
    /// One leg, or the two legs of an ST 2022-7 pair, path 1 first.
    pub legs: Vec<Leg>,
    /// The reference clock, when known.
    pub clock: Option<Clock>,
    /// The time to live of multicast packets.
    pub ttl: u8,
}

impl Description {
    /// Says why the stream cannot be sent or received, if it cannot.
    pub fn check(&self) -> Result<(), String> {
        self.media.check()?;
        if !(96..=127).contains(&self.payload_type) {
            return Err(format!("payload type {} is not a dynamic one, 96 to 127", self.payload_type));
        }
        match self.legs.as_slice() {
            [] => return Err("the stream has no destination".into()),
            [_] => {}
            [a, b] => {
                // ST 2110-10:2022 §8.5 and RFC 7104: a multicast group is one path, whatever
                // the port.
                let same = if a.destination.ip().is_multicast() {
                    a.destination.ip() == b.destination.ip()
                } else {
                    a.destination == b.destination
                };
                if same && a.source == b.source {
                    return Err(format!(
                        "both legs go to {} from the same source: ST 2022-7 legs need different destination or source addresses",
                        a.destination.ip()
                    ));
                }
            }
            more => return Err(format!("{} legs: a stream has one, or two for ST 2022-7", more.len())),
        }
        for leg in &self.legs {
            if leg.destination.port() == 0 {
                return Err(format!("{} has no port", leg.destination.ip()));
            }
        }
        Ok(())
    }

    /// The SDP file, following ST 2110-10 §8 and, for two legs, RFC 7104's separate
    /// destination or source addresses with `a=group:DUP`. The session name goes on one
    /// line, `-` when it is empty.
    pub fn sdp(&self, session_id: u64) -> String {
        let origin = self.legs.first().and_then(|l| l.source).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let name = self.name.replace(['\r', '\n'], " ");
        let name = if name.trim().is_empty() { "-" } else { name.trim() };
        let mut text = format!("v=0\r\no=- {session_id} {session_id} IN IP4 {origin}\r\ns={name}\r\nt=0 0\r\n");
        let mids = ["primary", "secondary"];
        if self.legs.len() > 1 {
            text.push_str(&format!("a=group:DUP {}\r\n", mids[..self.legs.len()].join(" ")));
        }
        let pt = self.payload_type;
        for (i, leg) in self.legs.iter().enumerate() {
            let (kind, rtpmap) = match &self.media {
                Media::Video(_) => ("video", "raw/90000".to_string()),
                Media::Audio(a) => ("audio", format!("{}/{}/{}", a.encoding(), a.sample_rate, a.channels)),
            };
            let group = leg.destination.ip();
            text.push_str(&format!("m={kind} {} RTP/AVP {pt}\r\n", leg.destination.port()));
            if group.is_multicast() {
                text.push_str(&format!("c=IN IP4 {group}/{}\r\n", self.ttl));
                if let Some(source) = leg.source {
                    text.push_str(&format!("a=source-filter: incl IN IP4 {group} {source}\r\n"));
                }
            } else {
                text.push_str(&format!("c=IN IP4 {group}\r\n"));
            }
            text.push_str(&format!("a=rtpmap:{pt} {rtpmap}\r\n"));
            match &self.media {
                Media::Video(v) => text.push_str(&format!("a=fmtp:{pt} {}\r\n", v.fmtp())),
                Media::Audio(a) => {
                    text.push_str(&format!("a=fmtp:{pt} channel-order={}\r\n", a.channel_order()));
                    text.push_str(&format!("a=ptime:{}\r\n", a.ptime()));
                }
            }
            if let Some(clock) = &self.clock {
                text.push_str(&format!("a=ts-refclk:{}\r\n", clock.sdp_value()));
            }
            text.push_str("a=mediaclk:direct=0\r\n");
            if self.legs.len() > 1 {
                text.push_str(&format!("a=mid:{}\r\n", mids[i]));
            }
        }
        text
    }

    /// Reads the stream an SDP file describes, with notes on anything left out. The
    /// legs are the ones an IS-05 Receiver would join ([`st2110_connect::legs`]), and
    /// the format comes from the first leg's media section.
    pub fn parse(text: &str) -> Result<(Self, Vec<String>), String> {
        let legs = st2110_connect::legs(text)?;
        let mut notes = legs.notes;
        let (sdp, _) = st2110_sdp::parse(text);
        let sections = leg_sections(&sdp);
        let mut parsed = Vec::new();
        for (leg, &section) in legs.legs.iter().zip(sections.iter().cycle()) {
            let ip: Ipv4Addr = leg.destination.parse().map_err(|_| {
                format!("{} is not an IPv4 address: IPv6 streams are not supported yet", leg.destination)
            })?;
            let source = match &leg.source_ip {
                Some(source) => Some(source.parse().map_err(|_| format!("source {source} is not an IPv4 address"))?),
                None => None,
            };
            parsed.push((Leg { destination: SocketAddrV4::new(ip, leg.destination_port), source }, section));
        }
        if parsed.len() > 2 {
            notes.push(format!("only the first two of {} legs are received", parsed.len()));
            parsed.truncate(2);
        }
        let (first, section) = parsed.first().copied().ok_or("the SDP file describes no stream")?;
        let section = &sdp.media[section];
        let (media, payload_type) = media(section)?;
        for &(_, other) in &parsed[1..] {
            let (_, pt) = self::media(&sdp.media[other])?;
            if pt != payload_type {
                return Err(format!(
                    "the legs use payload types {payload_type} and {pt}: ST 2022-7 legs carry identical packets"
                ));
            }
        }
        let clock = match section.attribute("ts-refclk").or_else(|| sdp.session.attribute("ts-refclk")) {
            None => None,
            Some(a) => match RefClock::parse(a.text()) {
                Ok(RefClock::Ptp { traceable: true, .. }) => Some(Clock::Traceable),
                Ok(RefClock::Ptp { grandmaster: Some(grandmaster), domain, .. }) => {
                    Some(Clock::Ptp { grandmaster, domain })
                }
                Ok(RefClock::LocalMac { address }) => Some(Clock::LocalMac(address)),
                _ => None,
            },
        };
        let ttl = section
            .field('c')
            .or_else(|| sdp.session.field('c'))
            .and_then(|c| parse_connection(&c.value).ok())
            .and_then(|c| c.ttl)
            .unwrap_or(if first.destination.ip().is_multicast() { 64 } else { 1 });
        let name = sdp.session.field('s').map(|s| s.value.trim().to_string()).unwrap_or_default();
        let description =
            Self { name, media, payload_type, legs: parsed.iter().map(|&(leg, _)| leg).collect(), clock, ttl };
        description.check()?;
        Ok((description, notes))
    }
}

/// The media sections the legs come from, as [`st2110_connect::legs`] picks them: those
/// the session's `a=group:DUP` names, or else the first.
fn leg_sections(sdp: &st2110_sdp::SessionDescription) -> Vec<usize> {
    let group: Option<Vec<&str>> = sdp.session.attributes_named("group").find_map(|a| {
        let mut words = a.text().split_whitespace();
        words.next().filter(|semantics| semantics.eq_ignore_ascii_case("DUP"))?;
        Some(words.collect())
    });
    match group {
        Some(group) => (0..sdp.media.len())
            .filter(|&i| sdp.media[i].attribute("mid").is_some_and(|mid| group.contains(&mid.text())))
            .collect(),
        None => vec![0],
    }
}

/// The format and payload type of a media section's first payload type.
fn media(section: &Section) -> Result<(Media, u8), String> {
    let mline = parse_media_line(&section.fields[0].value)?;
    let pt_text = &mline.formats[0];
    let payload_type: u8 = pt_text.parse().map_err(|_| format!("payload type {pt_text} is not a number"))?;
    let for_pt = |name: &str| {
        section
            .attributes_named(name)
            .map(|a| a.text())
            .find(|text| text.split_once(char::is_whitespace).is_some_and(|(pt, _)| pt == pt_text) || *text == pt_text)
    };
    let rtpmap =
        for_pt("rtpmap").ok_or_else(|| format!("the SDP file gives no a=rtpmap for payload type {pt_text}"))?;
    let rtpmap = parse_rtpmap(rtpmap)?;
    let fmtp = for_pt("fmtp").map(|text| text.split_once(char::is_whitespace).map_or("", |(_, rest)| rest));
    let (fmtp, _) = Fmtp::parse(fmtp.unwrap_or_default());
    let encoding = rtpmap.encoding.to_ascii_uppercase();
    let media = match (mline.media.as_str(), encoding.as_str()) {
        ("video", "RAW") => {
            if rtpmap.clock_rate != 90_000 {
                return Err(format!("raw video at {} Hz: ST 2110-20 uses a 90 kHz clock", rtpmap.clock_rate));
            }
            Media::Video(VideoFormat::from_fmtp(|name| fmtp.value(name).map(str::to_string), |name| fmtp.has(name))?)
        }
        ("audio", "L24" | "L16") => {
            let channels = match rtpmap.params.as_deref() {
                None => 1,
                Some(n) => n.trim().parse().map_err(|_| format!("{n} is not a channel count"))?,
            };
            let ptime = section.attribute("ptime").map(|a| a.text()).unwrap_or("1");
            let ms: f64 = ptime
                .parse()
                .ok()
                .filter(|ms: &f64| *ms > 0.0 && *ms <= 4.0)
                .ok_or_else(|| format!("a=ptime:{ptime} is not a packet time up to 4 ms"))?;
            let format = AudioFormat {
                channels,
                sample_rate: rtpmap.clock_rate,
                bits: if encoding == "L16" { 16 } else { 24 },
                samples_per_packet: samples_in(rtpmap.clock_rate, ms),
            };
            format.check()?;
            Media::Audio(format)
        }
        (kind, _) => {
            return Err(format!(
                "{kind} {}: only ST 2110-20 video (raw) and ST 2110-30 audio (L24, L16) can be received",
                rtpmap.encoding
            ));
        }
    };
    Ok((media, payload_type))
}

#[cfg(test)]
mod tests {
    use st2110_sdp::{Rational, Severity};

    use super::*;

    fn leg(destination: &str, source: Option<&str>) -> Leg {
        Leg { destination: destination.parse().unwrap(), source: source.map(|s| s.parse().unwrap()) }
    }

    fn video() -> Description {
        Description {
            name: "Bars".into(),
            media: Media::Video(VideoFormat::new(1920, 1080, Rational::new(50, 1).unwrap())),
            payload_type: 96,
            legs: vec![leg("239.10.1.1:5004", Some("192.168.1.10")), leg("239.20.1.1:5004", Some("192.168.2.10"))],
            clock: Some(Clock::parse("08-00-11-FF-FE-21-E1-B0:127").unwrap()),
            ttl: 32,
        }
    }

    #[test]
    fn writes_sdp_the_linter_passes_and_reads_it_back() {
        let d = video();
        let text = d.sdp(42);
        assert!(text.contains("a=group:DUP primary secondary\r\n"), "{text}");
        assert!(text.contains("a=source-filter: incl IN IP4 239.20.1.1 192.168.2.10\r\n"), "{text}");
        assert!(text.contains("a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:127\r\n"), "{text}");
        let report = st2110_sdp::lint(&text);
        let findings: Vec<_> =
            report.diagnostics.iter().filter(|d| d.severity != Severity::Info).map(|d| d.message.clone()).collect();
        assert!(findings.is_empty(), "{findings:?}\n{text}");
        let (back, notes) = Description::parse(&text).unwrap();
        assert_eq!(back, d);
        assert!(notes.is_empty());

        let audio = Description {
            name: "Tone".into(),
            media: Media::Audio(AudioFormat::new(8).with_packet_time(0.125).unwrap()),
            payload_type: 97,
            legs: vec![leg("10.0.0.2:5006", None)],
            clock: Some(Clock::Traceable),
            ttl: 64,
        };
        let text = audio.sdp(7);
        assert!(
            text.contains("a=rtpmap:97 L24/48000/8\r\na=fmtp:97 channel-order=SMPTE2110.(U08)\r\na=ptime:0.125\r\n")
        );
        assert!(!st2110_sdp::lint(&text).has_errors(), "{text}");
        let (back, _) = Description::parse(&text).unwrap();
        assert_eq!(back.media, audio.media);
        assert_eq!(back.legs, audio.legs);
    }

    #[test]
    fn clocks() {
        assert_eq!(Clock::parse("traceable").unwrap(), Clock::Traceable);
        assert_eq!(Clock::parse("localmac=CA-FE-01-CA-FE-02").unwrap().sdp_value(), "localmac=CA-FE-01-CA-FE-02");
        assert_eq!(
            Clock::parse("ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:0").unwrap().sdp_value(),
            "ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:0"
        );
        assert!(Clock::parse("ntp=pool.ntp.org").unwrap_err().contains("not a reference clock"));
        assert!(Clock::parse("localmac=nope").is_err());
    }

    #[test]
    fn names_go_on_one_line() {
        let mut d = video();
        d.name = "Bars\r\na=tool:evil".into();
        assert!(d.sdp(1).contains("\r\ns=Bars  a=tool:evil\r\n"));
        d.name = " \n ".into();
        let text = d.sdp(1);
        assert!(text.contains("\r\ns=-\r\n"), "{text}");
        assert!(!st2110_sdp::lint(&text).has_errors(), "{text}");
    }

    #[test]
    fn refuses_what_it_cannot_receive() {
        let mut d = video();
        d.legs[1] = d.legs[0];
        assert!(d.check().unwrap_err().contains("different destination or source"));
        // A multicast group is one path, whatever the port.
        d.legs[1].destination.set_port(5006);
        assert!(d.check().unwrap_err().contains("different destination or source"));
        d.legs[1].source = Some(Ipv4Addr::new(192, 168, 2, 10));
        assert!(d.check().is_ok());
        // Unicast to one address can take two ports.
        d.legs = vec![leg("10.0.0.2:5004", Some("10.0.0.1")), leg("10.0.0.2:5006", Some("10.0.0.1"))];
        assert!(d.check().is_ok());
        d.legs.truncate(1);
        d.payload_type = 33;
        assert!(d.check().unwrap_err().contains("dynamic"));
        let anc = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=x\r\nt=0 0\r\nm=video 5004 RTP/AVP 100\r\n\
                   c=IN IP4 239.1.1.1/32\r\na=rtpmap:100 smpte291/90000\r\n";
        assert!(Description::parse(anc).unwrap_err().contains("only ST 2110-20 video"));
        let v6 = "v=0\r\no=- 1 1 IN IP6 ::1\r\ns=x\r\nt=0 0\r\nm=audio 5004 RTP/AVP 97\r\n\
                  c=IN IP6 ff3e::1\r\na=rtpmap:97 L24/48000/2\r\n";
        assert!(Description::parse(v6).unwrap_err().contains("IPv6"));
    }
}
