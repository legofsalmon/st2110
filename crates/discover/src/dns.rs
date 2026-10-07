//! DNS messages (RFC 1035) as unicast DNS and multicast DNS (RFC 6762) carry them: the
//! questions DNS-SD browsing asks and the records that answer them.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

/// An IPv4 address.
pub const A: u16 = 1;
/// A pointer to another name: from a service type to each instance of it.
pub const PTR: u16 = 12;
/// Text strings: a service's `key=value` pairs.
pub const TXT: u16 = 16;
/// An IPv6 address.
pub const AAAA: u16 = 28;
/// A service's host and port (RFC 2782).
pub const SRV: u16 = 33;
/// The EDNS(0) pseudo-record (RFC 6891), which offers room for a larger response.
pub const OPT: u16 = 41;

/// The Internet class.
const IN: u16 = 1;

/// The top bit of a question's class asks for a unicast response, and of a record's
/// class tells a multicast DNS cache to flush older records of its name and type.
const TOP: u16 = 0x8000;

/// The longest name, in octets as written.
const NAME_LIMIT: usize = 255;

/// A domain name: its labels, compared without regard to ASCII case.
#[derive(Clone, Debug, Default)]
pub struct Name(Vec<String>);

impl Name {
    /// Reads a name written with dots, such as `_nmos-node._tcp.local`, where `\.` is a
    /// dot within a label and `\\` a backslash. A final dot is ignored.
    pub fn parse(text: &str) -> Self {
        let mut labels = Vec::new();
        let mut label = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => label.extend(chars.next()),
                '.' => labels.push(std::mem::take(&mut label)),
                c => label.push(c),
            }
        }
        if !label.is_empty() {
            labels.push(label);
        }
        Self(labels)
    }

    /// A name of these labels.
    pub fn from_labels(labels: Vec<String>) -> Self {
        Self(labels)
    }

    /// Its labels, the leftmost first.
    pub fn labels(&self) -> &[String] {
        &self.0
    }

    /// The name with `label` in front of it.
    pub fn child(&self, label: &str) -> Self {
        let mut labels = vec![label.to_string()];
        labels.extend(self.0.iter().cloned());
        Self(labels)
    }

    /// The leftmost label, such as a service instance's own name, and the rest.
    pub fn split_first(&self) -> Option<(&str, Self)> {
        let (first, rest) = self.0.split_first()?;
        Some((first, Self(rest.to_vec())))
    }

    /// Whether it ends with the labels of `suffix`.
    pub fn ends_with(&self, suffix: &Self) -> bool {
        self.0.len() >= suffix.0.len()
            && self.0[self.0.len() - suffix.0.len()..].iter().zip(&suffix.0).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    fn lowercase(&self) -> Vec<String> {
        self.0.iter().map(|l| l.to_ascii_lowercase()).collect()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lowercase().hash(state);
    }
}

impl fmt::Display for Name {
    /// The labels joined by dots, with a dot or backslash within a label escaped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, label) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            f.write_str(&label.replace('\\', "\\\\").replace('.', "\\."))?;
        }
        Ok(())
    }
}

/// What a record holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// Another name.
    Ptr(Name),
    /// A service's host and port.
    Srv {
        /// Lower is tried first.
        priority: u16,
        /// How often to pick it among those of one priority.
        weight: u16,
        /// The port.
        port: u16,
        /// The host.
        target: Name,
    },
    /// Text strings.
    Txt(Vec<Vec<u8>>),
    /// Anything else, as it came.
    Other(Vec<u8>),
}

/// A resource record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Whose record it is.
    pub name: Name,
    /// Its type, such as [`PTR`].
    pub kind: u16,
    /// Its class, without the multicast DNS cache-flush bit.
    pub class: u16,
    /// Whether a multicast DNS cache is to drop older records of this name and type.
    pub cache_flush: bool,
    /// Seconds it may be kept; 0 says it is gone.
    pub ttl: u32,
    /// What it holds.
    pub data: Data,
}

impl Record {
    /// A record in the Internet class.
    pub fn new(name: Name, ttl: u32, data: Data) -> Self {
        let kind = match &data {
            Data::A(_) => A,
            Data::Aaaa(_) => AAAA,
            Data::Ptr(_) => PTR,
            Data::Srv { .. } => SRV,
            Data::Txt(_) => TXT,
            Data::Other(_) => 0,
        };
        Self { name, kind, class: IN, cache_flush: false, ttl, data }
    }
}

/// A question: the records of one name and type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about.
    pub name: Name,
    /// The type of record wanted.
    pub kind: u16,
    /// Whether a multicast DNS responder is asked to answer by unicast.
    pub unicast: bool,
}

impl Question {
    /// A question in the Internet class, answered as the responder chooses.
    pub fn new(name: Name, kind: u16) -> Self {
        Self { name, kind, unicast: false }
    }
}

/// A DNS message: a query, or the response to one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The query identifier, which a unicast response repeats; 0 in multicast DNS.
    pub id: u16,
    /// Whether it is a response.
    pub response: bool,
    /// Whether the responder is the authority for the names.
    pub authoritative: bool,
    /// Whether the response was cut short to fit, so that it must be asked again over TCP.
    pub truncated: bool,
    /// Whether the server is to find the answer itself, as unicast queries ask.
    pub recursion_desired: bool,
    /// The response code: 0 for no error, 3 for a name that does not exist.
    pub rcode: u8,
    /// What is asked.
    pub questions: Vec<Question>,
    /// The records that answer it.
    pub answers: Vec<Record>,
    /// Records of the authorities for the names.
    pub authorities: Vec<Record>,
    /// Other records the responder expects to be wanted next.
    pub additionals: Vec<Record>,
}

impl Message {
    /// A query for `questions`.
    pub fn query(id: u16, questions: Vec<Question>) -> Self {
        Self { id, questions, ..Self::default() }
    }

    /// The records of the answer and additional sections, where DNS-SD answers come.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers.iter().chain(&self.additionals).filter(|r| r.kind != OPT)
    }

    /// The message as it goes on the wire, with names compressed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer { bytes: Vec::with_capacity(512), names: HashMap::new() };
        out.u16(self.id);
        let mut flags = u16::from(self.rcode & 0x0f);
        for (set, bit) in [
            (self.response, 0x8000),
            (self.authoritative, 0x0400),
            (self.truncated, 0x0200),
            (self.recursion_desired, 0x0100),
        ] {
            if set {
                flags |= bit;
            }
        }
        out.u16(flags);
        for count in [self.questions.len(), self.answers.len(), self.authorities.len(), self.additionals.len()] {
            out.u16(u16::try_from(count).unwrap_or(u16::MAX));
        }
        for q in &self.questions {
            out.name(&q.name);
            out.u16(q.kind);
            out.u16(IN | if q.unicast { TOP } else { 0 });
        }
        for r in self.answers.iter().chain(&self.authorities).chain(&self.additionals) {
            out.record(r);
        }
        out.bytes
    }

    /// Reads a message, or says why it cannot be read.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader { bytes, at: 0 };
        let id = r.u16()?;
        let flags = r.u16()?;
        let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
        let mut message = Self {
            id,
            response: flags & 0x8000 != 0,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            rcode: (flags & 0x0f) as u8,
            ..Self::default()
        };
        for _ in 0..counts[0] {
            let name = r.name()?;
            let kind = r.u16()?;
            let class = r.u16()?;
            message.questions.push(Question { name, kind, unicast: class & TOP != 0 });
        }
        for (count, section) in counts[1..].iter().zip(0..) {
            for _ in 0..*count {
                let record = r.record()?;
                match section {
                    0 => message.answers.push(record),
                    1 => message.authorities.push(record),
                    _ => message.additionals.push(record),
                }
            }
        }
        Ok(message)
    }
}

/// A DNS-SD service's `key=value` pairs (RFC 6763 §6), keys in lower case. A key
/// without a value reads as an empty one, and only the first of a key counts.
pub fn txt_pairs(strings: &[Vec<u8>]) -> BTreeMap<String, String> {
    let mut pairs = BTreeMap::new();
    for string in strings {
        let text = String::from_utf8_lossy(string);
        let (key, value) = text.split_once('=').unwrap_or((&text, ""));
        if !key.is_empty() {
            pairs.entry(key.to_ascii_lowercase()).or_insert_with(|| value.to_string());
        }
    }
    pairs
}

/// Writes a message, remembering where each name went so that later ones can point to it.
struct Writer {
    bytes: Vec<u8>,
    names: HashMap<Vec<String>, u16>,
}

impl Writer {
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn name(&mut self, name: &Name) {
        let lower = name.lowercase();
        for i in 0..name.0.len() {
            if let Some(&at) = self.names.get(&lower[i..]) {
                self.u16(0xc000 | at);
                return;
            }
            if let Ok(at) = u16::try_from(self.bytes.len())
                && at < 0x4000
            {
                self.names.insert(lower[i..].to_vec(), at);
            }
            let label = name.0[i].as_bytes();
            let label = &label[..label.len().min(63)];
            self.bytes.push(label.len() as u8);
            self.bytes.extend_from_slice(label);
        }
        self.bytes.push(0);
    }

    fn record(&mut self, r: &Record) {
        self.name(&r.name);
        self.u16(r.kind);
        self.u16(r.class | if r.cache_flush { TOP } else { 0 });
        self.bytes.extend_from_slice(&r.ttl.to_be_bytes());
        let length_at = self.bytes.len();
        self.u16(0);
        match &r.data {
            Data::A(ip) => self.bytes.extend_from_slice(&ip.octets()),
            Data::Aaaa(ip) => self.bytes.extend_from_slice(&ip.octets()),
            Data::Ptr(name) => self.name(name),
            Data::Srv { priority, weight, port, target } => {
                self.u16(*priority);
                self.u16(*weight);
                self.u16(*port);
                self.name(target);
            }
            Data::Txt(strings) => {
                for s in strings {
                    let s = &s[..s.len().min(255)];
                    self.bytes.push(s.len() as u8);
                    self.bytes.extend_from_slice(s);
                }
                if strings.is_empty() {
                    self.bytes.push(0);
                }
            }
            Data::Other(bytes) => self.bytes.extend_from_slice(bytes),
        }
        let length = u16::try_from(self.bytes.len() - length_at - 2).unwrap_or(u16::MAX);
        self.bytes[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.at.checked_add(n).filter(|&end| end <= self.bytes.len());
        let end = end.ok_or_else(|| format!("the message ends at octet {} of {}", self.bytes.len(), self.at + n))?;
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a name, following compression pointers, each of which must point back.
    fn name(&mut self) -> Result<Name, String> {
        let mut labels = Vec::new();
        let mut at = self.at;
        let mut resume = None;
        let mut length = 0;
        loop {
            let &len = self.bytes.get(at).ok_or("a name runs off the end of the message")?;
            match len & 0xc0 {
                0x00 if len == 0 => {
                    at += 1;
                    break;
                }
                0x00 => {
                    let label = self.bytes.get(at + 1..at + 1 + usize::from(len)).ok_or("a label runs off the end")?;
                    length += label.len() + 1;
                    if length > NAME_LIMIT {
                        return Err("a name is longer than 255 octets".into());
                    }
                    labels.push(String::from_utf8_lossy(label).into_owned());
                    at += 1 + usize::from(len);
                }
                0xc0 => {
                    let &low = self.bytes.get(at + 1).ok_or("a name's pointer runs off the end")?;
                    let target = usize::from(u16::from_be_bytes([len & 0x3f, low]));
                    if target >= at {
                        return Err("a name's pointer does not point back".into());
                    }
                    resume.get_or_insert(at + 2);
                    at = target;
                }
                _ => return Err(format!("a label starts with the reserved bits {:#04x}", len & 0xc0)),
            }
        }
        self.at = resume.unwrap_or(at);
        Ok(Name(labels))
    }

    fn record(&mut self) -> Result<Record, String> {
        let name = self.name()?;
        let kind = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let length = usize::from(self.u16()?);
        let start = self.at;
        let end = start + length;
        if end > self.bytes.len() {
            return Err(format!("a record of {length} octets runs off the end of the message"));
        }
        let data = match kind {
            A if length == 4 => {
                let b = self.take(4)?;
                Data::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            AAAA if length == 16 => {
                let b: [u8; 16] = self.take(16)?.try_into().expect("16 octets");
                Data::Aaaa(Ipv6Addr::from(b))
            }
            PTR => Data::Ptr(self.name()?),
            SRV => Data::Srv { priority: self.u16()?, weight: self.u16()?, port: self.u16()?, target: self.name()? },
            TXT => {
                let mut strings = Vec::new();
                let mut at = start;
                while at < end {
                    let len = usize::from(self.bytes[at]);
                    let s = self.bytes.get(at + 1..at + 1 + len).filter(|_| at + 1 + len <= end);
                    strings.push(s.ok_or("a text string runs off the end of its record")?.to_vec());
                    at += 1 + len;
                }
                Data::Txt(strings)
            }
            _ => Data::Other(self.take(length)?.to_vec()),
        };
        if self.at > end {
            return Err(format!("a record's data runs past its {length} octets"));
        }
        self.at = end;
        Ok(Record { name, kind, class: class & !TOP, cache_flush: class & TOP != 0, ttl, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_compare_without_case_and_escape_dots() {
        let name = Name::parse("Camera\\.1._NMOS-node._tcp.local.");
        assert_eq!(name.labels(), ["Camera.1", "_NMOS-node", "_tcp", "local"]);
        assert_eq!(name, Name::parse("camera\\.1._nmos-node._tcp.LOCAL"));
        assert_eq!(name.to_string(), "Camera\\.1._NMOS-node._tcp.local");
        let (instance, service) = name.split_first().unwrap();
        assert_eq!((instance, service.to_string().as_str()), ("Camera.1", "_NMOS-node._tcp.local"));
        assert!(name.ends_with(&Name::parse("_nmos-node._tcp.local")) && !name.ends_with(&Name::parse("_tcp.lan")));
        assert_eq!(service.child("Camera.1"), name);
    }

    #[test]
    fn records_go_and_come_back_the_same() {
        let service = Name::parse("_nmos-node._tcp.local");
        let instance = service.child("Camera 1");
        let host = Name::parse("camera-1.local");
        let mut srv =
            Record::new(instance.clone(), 120, Data::Srv { priority: 0, weight: 0, port: 80, target: host.clone() });
        srv.cache_flush = true;
        let txt = b"api_proto=http api_ver=v1.0,v1.1,v1.2,v1.3 api_auth=false".split(|&b| b == b' ');
        let message = Message {
            response: true,
            authoritative: true,
            answers: vec![Record::new(service.clone(), 4500, Data::Ptr(instance.clone()))],
            additionals: vec![
                srv,
                Record::new(instance.clone(), 4500, Data::Txt(txt.map(<[u8]>::to_vec).collect())),
                Record::new(host.clone(), 120, Data::A(Ipv4Addr::new(192, 168, 10, 21))),
                Record::new(host, 120, Data::Aaaa("fe80::1".parse().unwrap())),
            ],
            ..Message::default()
        };
        let bytes = message.encode();
        assert_eq!(Message::decode(&bytes).unwrap(), message);
        // Each name after the first points back to where it was written.
        assert_eq!(bytes.windows(b"_nmos-node".len()).filter(|w| w == b"_nmos-node").count(), 1);
        let Data::Txt(strings) = &message.additionals[1].data else { unreachable!("TXT") };
        let pairs = txt_pairs(strings);
        assert_eq!((pairs["api_proto"].as_str(), pairs["api_ver"].as_str()), ("http", "v1.0,v1.1,v1.2,v1.3"));
    }

    #[test]
    fn questions_ask_for_unicast_with_the_top_bit() {
        let mut query = Message::query(0x1234, vec![Question::new(Name::parse("_nmos-query._tcp.local"), PTR)]);
        query.questions[0].unicast = true;
        query.recursion_desired = true;
        let bytes = query.encode();
        assert_eq!(&bytes[..4], [0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&bytes[bytes.len() - 4..], [0x00, 0x0c, 0x80, 0x01]);
        assert_eq!(Message::decode(&bytes).unwrap(), query);
    }

    #[test]
    fn refuses_what_runs_off_the_end_or_loops() {
        let message = Message::query(1, vec![Question::new(Name::parse("a.b"), A)]).encode();
        for cut in 0..message.len() {
            assert!(Message::decode(&message[..cut]).is_err(), "cut at {cut}");
        }
        // A name that points at itself.
        let mut looped = Message::query(1, vec![]).encode();
        looped[5] = 1;
        looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(Message::decode(&looped).unwrap_err().contains("does not point back"));
    }

    #[test]
    fn reads_a_pointer_written_by_hand() {
        // An answer to a PTR query, its instance's name pointing back to the service's.
        let bytes: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x0a, b'_', b'n', b'm', b'o', b's', b'-', b'n', b'o', b'd', b'e', 0x04, b'_', b't', b'c', b'p', 0x05, b'l',
            b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x0b, 0x08, b'C', b'a',
            b'm', b'e', b'r', b'a', b' ', b'1', 0xc0, 0x0c,
        ];
        let message = Message::decode(bytes).unwrap();
        assert!(message.response && message.authoritative);
        let record = &message.answers[0];
        assert_eq!((record.name.to_string().as_str(), record.ttl), ("_nmos-node._tcp.local", 4500));
        assert_eq!(record.data, Data::Ptr(Name::parse("Camera 1._nmos-node._tcp.local")));
    }
}
