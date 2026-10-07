//! SAP, the Session Announcement Protocol (RFC 2974): SDP files announced to a multicast
//! group, again and again, by whoever sends the streams they describe. AES67 devices
//! announce theirs this way, and some ST 2110 devices do too.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// The port SAP is sent to.
pub const PORT: u16 = 9875;

/// Where sessions in the administratively scoped range 239.255.0.0/16 are announced, the
/// highest address of that range (RFC 2974 §3), as AES67 devices announce theirs.
pub const ADMIN_LOCAL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 255), PORT);

/// Where sessions of global scope are announced (RFC 2974 §3).
pub const GLOBAL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 2, 127, 254), PORT);

/// The payload type of an SDP file.
const SDP: &str = "application/sdp";

/// The most a compressed payload may hold once inflated.
const INFLATED_LIMIT: usize = 1 << 20;

/// A session is forgotten when it has not been announced for ten times the interval
/// between its announcements, or an hour, whichever is longer (RFC 2974 §4).
const FORGET_AFTER: Duration = Duration::from_secs(3600);

/// The interval assumed for a session heard only once: the 30 seconds that AES67
/// devices announce at, rather than RFC 2974's five minutes or more, so that a sender
/// that stops soon after it starts is soon marked. Once a session is heard again, its
/// own interval counts.
const ASSUMED_INTERVAL: Duration = Duration::from_secs(30);

/// How many of the gaps between a session's announcements its interval is the longest
/// of.
const GAPS_KEPT: usize = 4;

/// A SAP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Whether it deletes the session rather than announcing it.
    pub deletion: bool,
    /// The announcer's address, the originating source.
    pub origin: IpAddr,
    /// The message identifier hash, which with the origin names this version of the
    /// announcement.
    pub hash: u16,
    /// The payload type, such as `application/sdp`; `None` where the packet leaves it
    /// out, as SAPv1 packets did.
    pub payload_type: Option<String>,
    /// The payload: the session's SDP file, or for a deletion as much of it as names
    /// the session.
    pub payload: String,
}

/// Reads a SAP packet, inflating a compressed payload, or says why it cannot be read:
/// another version of SAP, an encrypted payload, or one that is not an SDP file.
pub fn parse(bytes: &[u8]) -> Result<Packet, String> {
    let [first, auth_words, hash_high, hash_low, rest @ ..] = bytes else {
        return Err(format!("{} octets is too short for a SAP header", bytes.len()));
    };
    let version = first >> 5;
    if version != 1 {
        return Err(format!("SAP version {version}, where RFC 2974 sends 1"));
    }
    let (ipv6, deletion, encrypted, compressed) =
        (first & 0x10 != 0, first & 0x04 != 0, first & 0x02 != 0, first & 0x01 != 0);
    let origin_len = if ipv6 { 16 } else { 4 };
    let skip = origin_len + usize::from(*auth_words) * 4;
    if rest.len() < skip {
        return Err(format!("{} octets is too short for a SAP header and its authentication data", bytes.len()));
    }
    let origin = if ipv6 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).expect("16 octets")))
    } else {
        IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]))
    };
    if encrypted {
        return Err("the payload is encrypted".into());
    }
    let inflated;
    let mut payload = &rest[skip..];
    if compressed {
        inflated = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(payload, INFLATED_LIMIT)
            .map_err(|e| format!("the compressed payload cannot be inflated: {e}"))?;
        payload = &inflated;
    }
    // A payload type, ended by a zero octet, unless the payload starts as an SDP file does.
    let mut payload_type = None;
    if !payload.starts_with(b"v=0")
        && let Some(end) = payload.iter().position(|&b| b == 0)
    {
        payload_type = Some(String::from_utf8_lossy(&payload[..end]).trim().to_string());
        payload = &payload[end + 1..];
    }
    if let Some(kind) = &payload_type {
        let essence = kind.split(';').next().unwrap_or_default().trim();
        if !essence.eq_ignore_ascii_case(SDP) {
            return Err(format!("the payload is {kind}, not an SDP file"));
        }
    }
    Ok(Packet {
        deletion,
        origin,
        hash: u16::from_be_bytes([*hash_high, *hash_low]),
        payload_type,
        payload: String::from_utf8_lossy(payload).into_owned(),
    })
}

/// A message identifier hash for an SDP file, never 0: RFC 2974 §5 leaves the choice to
/// the announcer, as long as it changes when the file does. FNV-1a, folded.
pub fn hash(sdp: &str) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in sdp.as_bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    match ((h >> 16) ^ (h & 0xffff)) as u16 {
        0 => 1,
        folded => folded,
    }
}

/// A SAP packet that announces `sdp` from `origin`, or deletes it.
pub fn packet(origin: Ipv4Addr, sdp: &str, deletion: bool) -> Vec<u8> {
    let mut bytes = vec![0x20 | if deletion { 0x04 } else { 0 }, 0];
    bytes.extend_from_slice(&hash(sdp).to_be_bytes());
    bytes.extend_from_slice(&origin.octets());
    bytes.extend_from_slice(SDP.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(sdp.as_bytes());
    bytes
}

/// What names a session across versions of its SDP file: the `o=` line without the
/// session version (RFC 8866 §5.2), or `None` when the file has none.
pub fn session_id(sdp: &str) -> Option<String> {
    let line = sdp.lines().find_map(|line| line.trim().strip_prefix("o="))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [user, id, _version, net, kind, address] = fields.as_slice() else {
        return None;
    };
    Some(format!("{user} {id} {net} {kind} {address}"))
}

/// A session that has been announced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// The announcer's address.
    pub origin: IpAddr,
    /// The message identifier hash of the newest announcement.
    pub hash: u16,
    /// Its SDP file.
    pub sdp: String,
    /// When it was first heard.
    pub first: Instant,
    /// When it was last heard.
    pub last: Instant,
    /// How long it is between its announcements: the longest of the last few gaps, so
    /// that a copy heard in a second group or on a second network, a while after the
    /// first, does not shorten it.
    pub interval: Option<Duration>,
    /// The last few gaps between its announcements.
    gaps: Vec<Duration>,
    /// Whether it was stale when last looked at.
    marked_stale: bool,
}

impl Session {
    /// Whether it has not been heard for three times its interval, or 90 seconds when
    /// it has been heard once: the sender that announces it may have stopped.
    pub fn stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) > 3 * self.interval.unwrap_or(ASSUMED_INTERVAL)
    }

    fn forgotten(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) > FORGET_AFTER.max(10 * self.interval.unwrap_or(ASSUMED_INTERVAL))
    }
}

/// The sessions announced so far, kept as RFC 2974 §4 says a receiver keeps them.
#[derive(Clone, Debug, Default)]
pub struct Sessions {
    sessions: BTreeMap<String, Session>,
}

impl Sessions {
    /// Takes in a packet heard at `now`: a new session, a new version of one, or the
    /// deletion of one. Gives whether the sessions changed, counting a stale one heard
    /// again but not when each was heard.
    pub fn heard(&mut self, packet: &Packet, now: Instant) -> bool {
        let key = session_id(&packet.payload).unwrap_or_else(|| format!("{} {}", packet.origin, packet.hash));
        if packet.deletion {
            let before = self.sessions.len();
            self.sessions.retain(|k, s| *k != key && (s.origin, s.hash) != (packet.origin, packet.hash));
            return self.sessions.len() != before;
        }
        match self.sessions.get_mut(&key) {
            Some(session) => {
                // The same announcement on another port, or in another group, is not a repeat.
                let since = now.saturating_duration_since(session.last);
                if since >= Duration::from_secs(1) {
                    if session.gaps.len() == GAPS_KEPT {
                        session.gaps.remove(0);
                    }
                    session.gaps.push(since);
                    session.interval = session.gaps.iter().max().copied();
                }
                session.last = now;
                let changed = session.sdp != packet.payload || session.origin != packet.origin || session.marked_stale;
                session.marked_stale = false;
                (session.origin, session.hash, session.sdp) = (packet.origin, packet.hash, packet.payload.clone());
                changed
            }
            None => {
                let session = Session {
                    origin: packet.origin,
                    hash: packet.hash,
                    sdp: packet.payload.clone(),
                    first: now,
                    last: now,
                    interval: None,
                    gaps: Vec::new(),
                    marked_stale: false,
                };
                self.sessions.insert(key, session);
                true
            }
        }
    }

    /// Forgets the sessions that have not been announced for too long, and marks those
    /// gone stale; gives whether either changed anything.
    pub fn expire(&mut self, now: Instant) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.forgotten(now));
        let mut changed = self.sessions.len() != before;
        for session in self.sessions.values_mut() {
            let stale = session.stale(now);
            changed |= stale != session.marked_stale;
            session.marked_stale = stale;
        }
        changed
    }

    /// The sessions, keyed by what names each across versions.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Session)> {
        self.sessions.iter().map(|(k, s)| (k.as_str(), s))
    }

    /// How many there are.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGEBOX: &str = "v=0\r\no=- 1311738121 1311738121 IN IP4 192.168.10.30\r\ns=Stagebox 1-8\r\nt=0 0\r\n\
        m=audio 5004 RTP/AVP 97\r\nc=IN IP4 239.69.83.67/32\r\na=rtpmap:97 L24/48000/8\r\n";

    fn origin() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 10, 30)
    }

    #[test]
    fn reads_what_it_writes() {
        let bytes = packet(origin(), STAGEBOX, false);
        assert_eq!(bytes[0], 0x20, "version 1, IPv4, an announcement, neither encrypted nor compressed");
        let read = parse(&bytes).unwrap();
        assert_eq!(read.origin, IpAddr::V4(origin()));
        assert_eq!((read.deletion, read.hash), (false, hash(STAGEBOX)));
        assert_eq!((read.payload_type.as_deref(), read.payload.as_str()), (Some("application/sdp"), STAGEBOX));
        assert!(parse(&packet(origin(), STAGEBOX, true)).unwrap().deletion);
        assert_ne!(hash(STAGEBOX), hash(&STAGEBOX.replace("1-8", "9-16")));
    }

    #[test]
    fn reads_what_others_send() {
        // SAPv1's packets have no payload type; this one has a word of authentication
        // data, an IPv6 origin, and a compressed payload.
        let mut bytes = vec![0x31, 1, 0xab, 0xcd];
        bytes.extend_from_slice(&"fd00::30".parse::<Ipv6Addr>().unwrap().octets());
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        bytes.extend_from_slice(&miniz_oxide::deflate::compress_to_vec_zlib(STAGEBOX.as_bytes(), 6));
        let read = parse(&bytes).unwrap();
        assert_eq!((read.origin, read.hash), ("fd00::30".parse::<IpAddr>().unwrap(), 0xabcd));
        assert_eq!((read.payload_type, read.payload.as_str()), (None, STAGEBOX));
        // Parameters on the payload type, and any case.
        let mut bytes = vec![0x20, 0, 0x12, 0x34, 192, 168, 10, 30];
        bytes.extend_from_slice(b"Application/SDP; charset=utf-8\0");
        bytes.extend_from_slice(STAGEBOX.as_bytes());
        assert_eq!(parse(&bytes).unwrap().payload, STAGEBOX);
    }

    #[test]
    fn says_what_it_cannot_read() {
        let mut bytes = packet(origin(), STAGEBOX, false);
        bytes[0] = 0x22;
        assert_eq!(parse(&bytes).unwrap_err(), "the payload is encrypted");
        bytes[0] = 0x40;
        assert_eq!(parse(&bytes).unwrap_err(), "SAP version 2, where RFC 2974 sends 1");
        let mut bytes = vec![0x20, 0, 0, 1, 10, 0, 0, 1];
        bytes.extend_from_slice(b"application/x-other\0hello");
        assert_eq!(parse(&bytes).unwrap_err(), "the payload is application/x-other, not an SDP file");
        assert!(parse(&[0x20, 9, 0, 1, 10, 0, 0, 1]).unwrap_err().contains("authentication data"));
        assert!(parse(&[0x20]).unwrap_err().contains("too short"));
        let mut bytes = vec![0x21, 0, 0, 1, 10, 0, 0, 1];
        bytes.extend_from_slice(b"not zlib");
        assert!(parse(&bytes).unwrap_err().starts_with("the compressed payload cannot be inflated"));
    }

    #[test]
    fn names_a_session_by_its_origin_line() {
        assert_eq!(session_id(STAGEBOX).as_deref(), Some("- 1311738121 IN IP4 192.168.10.30"));
        let newer = STAGEBOX.replace("1311738121 1311738121", "1311738121 1311738122");
        assert_eq!(session_id(&newer), session_id(STAGEBOX));
        assert_eq!(session_id("v=0\r\ns=-\r\n"), None);
    }

    #[test]
    fn keeps_sessions_until_deleted_or_long_unheard() {
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        let mut sessions = Sessions::default();
        let announced = parse(&packet(origin(), STAGEBOX, false)).unwrap();
        assert!(sessions.heard(&announced, at(0)));
        // Heard once, it is taken to come every 30 s.
        assert!(!sessions.iter().next().unwrap().1.stale(at(90)) && sessions.iter().next().unwrap().1.stale(at(91)));
        // The same packet on a second group, and again 40 s later.
        assert!(!sessions.heard(&announced, at(0)));
        assert!(!sessions.heard(&announced, at(40)));
        let (_, session) = sessions.iter().next().unwrap();
        assert_eq!((session.first, session.last, session.interval), (at(0), at(40), Some(Duration::from_secs(40))));
        assert!(!session.stale(at(160)) && session.stale(at(161)));
        // A new version replaces the old.
        let newer = STAGEBOX.replace("1311738121 1311738121", "1311738121 1311738122");
        assert!(sessions.heard(&parse(&packet(origin(), &newer, false)).unwrap(), at(60)));
        assert_eq!((sessions.len(), sessions.iter().next().unwrap().1.sdp.as_str()), (1, newer.as_str()));
        // Marked stale after three intervals, and forgotten after an hour unheard, as
        // ten intervals are less.
        assert!(!sessions.expire(at(60 + 120)) && sessions.expire(at(60 + 121)));
        assert!(!sessions.expire(at(60 + 3600)));
        assert!(sessions.expire(at(60 + 3601)) && sessions.is_empty());
        // Or deleted, by the deletion of either version.
        sessions.heard(&announced, at(0));
        assert!(sessions.heard(&parse(&packet(origin(), &newer, true)).unwrap(), at(1)));
        assert!(sessions.is_empty());
        // A deletion that names nothing announced changes nothing.
        assert!(!sessions.heard(&parse(&packet(origin(), STAGEBOX, true)).unwrap(), at(2)));
    }

    #[test]
    fn says_when_a_session_goes_stale_and_when_it_is_heard_again() {
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        let mut sessions = Sessions::default();
        let announced = parse(&packet(origin(), STAGEBOX, false)).unwrap();
        sessions.heard(&announced, at(0));
        assert!(!sessions.expire(at(90)));
        assert!(sessions.expire(at(91)) && sessions.iter().next().unwrap().1.stale(at(91)));
        assert!(!sessions.expire(at(92)));
        assert!(sessions.heard(&announced, at(100)));
        assert!(!sessions.heard(&announced, at(130)) && !sessions.expire(at(131)));
    }

    #[test]
    fn a_second_copy_of_each_announcement_does_not_shorten_the_interval() {
        let start = Instant::now();
        let mut sessions = Sessions::default();
        let announced = parse(&packet(origin(), STAGEBOX, false)).unwrap();
        // Every 30 s, and a copy from a second network 5 s after each.
        for s in [0, 5, 30, 35, 60, 65, 90, 95] {
            sessions.heard(&announced, start + Duration::from_secs(s));
        }
        let (_, session) = sessions.iter().next().unwrap();
        assert_eq!(session.interval, Some(Duration::from_secs(25)));
        assert!(!session.stale(start + Duration::from_secs(95 + 75)));
    }
}
