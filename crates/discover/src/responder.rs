//! A multicast DNS responder (RFC 6762) for one DNS-SD service instance (RFC 6763), as
//! a Node needs to be found peer to peer where there is no registry (IS-04 v1.3
//! Discovery: Peer to Peer).
//!
//! It shares port 5353 with the system's own responder, as [`crate::net`]'s querier
//! does. It claims a name of its own by probing three times, a quarter of a second
//! apart, taking `Name (2)`, `Name (3)` and so on when another responder answers for
//! the one it wants (§8.1, §9); it announces the instance twice, a second apart (§8.3),
//! and again when its text pairs change (§8.4); it answers the questions asked about
//! it, leaving out what the asker already knows (§7.1), and by unicast to a querier
//! that asks from a port of its own (§6.7); and it says goodbye when it stops (§10.1).
//!
//! It is kept simple: IPv4 only, one instance and its own host name, answers sent at
//! once rather than after a random delay, and two responders that probe for one name
//! at the same moment are not told apart by the tie-break of §8.2.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use socket2::Socket;

use crate::dns::{self, Data, Message, Name, Question, Record};
use crate::net::{interfaces, join, shared};

/// How long the records that name a host live: two minutes (RFC 6762 §10).
const HOST_TTL: u32 = 120;

/// How long the others live: 75 minutes.
const OTHER_TTL: u32 = 4500;

/// The longest a record in a response to a one-shot query may live (RFC 6762 §6.7).
const LEGACY_TTL: u32 = 10;

/// Where DNS-SD service types are listed (RFC 6763 §9).
const SERVICES: &str = "_services._dns-sd._udp.local";

/// Probes sent before a name is taken, and the time between them (RFC 6762 §8.1).
const PROBES: u32 = 3;
const PROBE_GAP: Duration = Duration::from_millis(250);

/// Announcements sent, and the time between them (RFC 6762 §8.3).
const ANNOUNCEMENTS: u32 = 2;
const ANNOUNCE_GAP: Duration = Duration::from_secs(1);

/// How long the socket waits for a datagram before the thread looks up again.
const WAIT: Duration = Duration::from_millis(50);

/// The longest label, in octets.
const LABEL_LIMIT: usize = 63;

/// A DNS-SD service instance to advertise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    /// The service type, such as `_nmos-node._tcp`.
    pub service: String,
    /// The instance's own name, such as `Camera 1`.
    pub name: String,
    /// The host's own label, such as `camera-1`, for the host `camera-1.local`.
    pub host: String,
    /// The port the service is on.
    pub port: u16,
    /// The host's IPv4 address.
    pub address: Ipv4Addr,
    /// Its text pairs, in order.
    pub txt: Vec<(String, String)>,
}

impl Instance {
    /// The service type's full name, such as `_nmos-node._tcp.local`.
    pub fn service_name(&self) -> Name {
        Name::parse(&format!("{}.local", self.service))
    }

    /// The instance's full name, such as `Camera 1._nmos-node._tcp.local`.
    pub fn full_name(&self) -> Name {
        self.service_name().child(&self.name)
    }

    /// The host's full name, such as `camera-1.local`.
    pub fn host_name(&self) -> Name {
        Name::from_labels(vec![self.host.clone(), "local".into()])
    }

    /// The instance as it is named after `conflicts` conflicts: `Camera 1 (2)` on
    /// `camera-1-2.local` after the first, each label kept within 63 octets.
    pub fn renamed(&self, conflicts: u32) -> Self {
        if conflicts == 0 {
            return self.clone();
        }
        let n = conflicts + 1;
        let name = format!("{} ({n})", shorten(&self.name, LABEL_LIMIT - format!(" ({n})").len()));
        let host = format!("{}-{n}", shorten(&self.host, LABEL_LIMIT - format!("-{n}").len()));
        Self { name, host, ..self.clone() }
    }

    fn srv(&self) -> Data {
        Data::Srv { priority: 0, weight: 0, port: self.port, target: self.host_name() }
    }

    fn txt_data(&self) -> Data {
        Data::Txt(self.txt.iter().map(|(k, v)| format!("{k}={v}").into_bytes()).collect())
    }

    /// Its records: the service type's pointer to it, its SRV and TXT records, the
    /// host's address, and the service type in the list of types. Those only it can
    /// hold tell caches to flush what they had of their name and type (§10.2).
    pub fn records(&self) -> Vec<Record> {
        let unique = |name: Name, ttl, data| Record { cache_flush: true, ..Record::new(name, ttl, data) };
        vec![
            Record::new(self.service_name(), OTHER_TTL, Data::Ptr(self.full_name())),
            unique(self.full_name(), HOST_TTL, self.srv()),
            unique(self.full_name(), OTHER_TTL, self.txt_data()),
            unique(self.host_name(), HOST_TTL, Data::A(self.address)),
            Record::new(Name::parse(SERVICES), OTHER_TTL, Data::Ptr(self.service_name())),
        ]
    }

    /// The probe for its names: a question about each, asking for a unicast answer,
    /// with the records it means to hold (§8.1, §8.2).
    pub fn probe(&self) -> Message {
        let ask = |name| Question { unicast: true, ..Question::new(name, dns::ANY) };
        let mut probe = Message::query(0, vec![ask(self.full_name()), ask(self.host_name())]);
        probe.authorities = self.records().into_iter().filter(|r| r.cache_flush).map(plain).collect();
        probe
    }

    /// The announcement of every record (§8.3).
    pub fn announcement(&self) -> Message {
        Message { response: true, authoritative: true, answers: self.records(), ..Message::default() }
    }

    /// The goodbye: every record with no time to live left (§10.1).
    pub fn goodbye(&self) -> Message {
        let mut goodbye = self.announcement();
        goodbye.answers.iter_mut().for_each(|r| r.ttl = 0);
        goodbye
    }

    /// The response to `query`, when it asks about the instance and does not already
    /// know every answer: the records asked for, and those the asker will want next as
    /// additional records (RFC 6763 §12). To a `legacy` querier, one asking from a port
    /// other than 5353, the response repeats its identifier and questions, and its
    /// records live 10 s at most and flush nothing (§6.7).
    pub fn answer(&self, query: &Message, legacy: bool) -> Option<Message> {
        if query.response {
            return None;
        }
        let records = self.records();
        let mut answers: Vec<Record> = Vec::new();
        for question in &query.questions {
            for record in &records {
                let asked = question.kind == record.kind || question.kind == dns::ANY;
                if asked && question.name == record.name && !answers.contains(record) {
                    answers.push(record.clone());
                }
            }
        }
        // Known-answer suppression: what the asker holds for at least half its life (§7.1).
        let known = |r: &Record| {
            query.answers.iter().any(|k| k.name == r.name && k.kind == r.kind && k.data == r.data && k.ttl >= r.ttl / 2)
        };
        answers.retain(|r| !known(r));
        if answers.is_empty() {
            return None;
        }
        let mut additionals: Vec<Record> = Vec::new();
        for answer in &answers {
            let next: &[u16] = match answer.data {
                Data::Ptr(ref to) if *to == self.full_name() => &[dns::SRV, dns::TXT, dns::A],
                Data::Srv { .. } => &[dns::A],
                _ => &[],
            };
            for record in &records {
                let wanted = next.contains(&record.kind) && (record.kind == dns::A || record.name == self.full_name());
                if wanted && !answers.contains(record) && !additionals.contains(record) {
                    additionals.push(record.clone());
                }
            }
        }
        let mut response = Message { response: true, authoritative: true, answers, additionals, ..Message::default() };
        if legacy {
            response.id = query.id;
            response.questions.clone_from(&query.questions);
            for record in response.answers.iter_mut().chain(&mut response.additionals) {
                record.ttl = record.ttl.min(LEGACY_TTL);
                record.cache_flush = false;
            }
        }
        Some(response)
    }

    /// Whether `message` shows another responder holding one of its names: a response
    /// with an SRV record of its instance's name, or an address of its host's, that is
    /// not its own (§9). Its own, heard back, are not.
    pub fn conflicts(&self, message: &Message) -> bool {
        let (instance, host) = (self.full_name(), self.host_name());
        message.response
            && message.answers.iter().chain(&message.authorities).chain(&message.additionals).any(|r| {
                r.ttl > 0
                    && ((r.kind == dns::SRV && r.name == instance && r.data != self.srv())
                        || (r.kind == dns::A && r.name == host && r.data != Data::A(self.address)))
            })
    }
}

/// A record as a probe's authority section has it, without the cache-flush bit.
fn plain(record: Record) -> Record {
    Record { cache_flush: false, ..record }
}

/// `text` cut to at most `limit` octets, at a character's edge.
fn shorten(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A host label made from a machine's name: its first label, in lower case, with only
/// letters, digits and hyphens.
pub fn host_label(hostname: &str) -> String {
    let first = hostname.split('.').next().unwrap_or_default().to_ascii_lowercase();
    let label: String = first.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let label = label.trim_matches('-');
    if label.is_empty() { "host".into() } else { shorten(label, LABEL_LIMIT).to_string() }
}

enum Command {
    Txt(Vec<(String, String)>),
    Stop,
}

/// A responder at work on its own thread, until it is stopped or dropped, when it says
/// goodbye.
pub struct Responder {
    commands: Sender<Command>,
    thread: Option<thread::JoinHandle<()>>,
    name: Arc<Mutex<String>>,
}

impl Responder {
    /// Starts advertising `instance` at `to`, the multicast DNS group ([`crate::MDNS`]) or
    /// another for a test: joins it on the interface with the instance's address, or
    /// the one the system picks when no interface has it, and starts probing for its
    /// name.
    pub fn start(instance: Instance, to: SocketAddrV4) -> io::Result<Self> {
        let socket = open(instance.address, to)?;
        let (commands, heard) = mpsc::channel();
        let name = Arc::new(Mutex::new(instance.name.clone()));
        let named = name.clone();
        let thread = thread::Builder::new()
            .name("mdns-responder".into())
            .spawn(move || run(&socket, to, instance, &heard, &named))?;
        Ok(Self { commands, thread: Some(thread), name })
    }

    /// The instance name it holds, or is probing for.
    pub fn name(&self) -> String {
        self.name.lock().map(|n| n.clone()).unwrap_or_default()
    }

    /// Changes the text pairs, and announces them.
    pub fn set_txt(&self, txt: Vec<(String, String)>) {
        let _ = self.commands.send(Command::Txt(txt));
    }

    /// Says goodbye and stops.
    pub fn stop(mut self) {
        self.finish();
    }

    fn finish(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The responder's socket: on the group's port, shared, in the group on the interface
/// with `address`, sending there too.
fn open(address: Ipv4Addr, to: SocketAddrV4) -> io::Result<UdpSocket> {
    let socket: Socket = shared(to.port())?;
    let on: Vec<Ipv4Addr> = interfaces().into_iter().map(|i| i.address).filter(|a| *a == address).collect();
    join(&socket, *to.ip(), &on)?;
    if let Some(interface) = on.first() {
        socket.set_multicast_if_v4(interface)?;
    }
    // Responders ignore multicast DNS from beyond the link (RFC 6762 §11).
    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_read_timeout(Some(WAIT))?;
    Ok(socket.into())
}

/// Where the responder has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Probing for its names: probes sent so far, and when the next is due.
    Probing(u32, Instant),
    /// Announcing: announcements sent so far, and when the next is due.
    Announcing(u32, Instant),
    /// Answering.
    Settled,
}

fn run(socket: &UdpSocket, to: SocketAddrV4, wanted: Instance, commands: &Receiver<Command>, named: &Mutex<String>) {
    let mut base = wanted;
    let mut conflicts = 0;
    let mut instance = base.clone();
    let mut phase = Phase::Probing(0, Instant::now());
    let mut buffer = vec![0u8; 9000];
    let send = |message: &Message, to: SocketAddrV4| {
        let _ = socket.send_to(&message.encode(), to);
    };
    loop {
        match commands.try_recv() {
            Ok(Command::Txt(txt)) => {
                base.txt.clone_from(&txt);
                instance.txt = txt;
                if !matches!(phase, Phase::Probing(..)) {
                    phase = Phase::Announcing(0, Instant::now());
                }
            }
            Ok(Command::Stop) | Err(TryRecvError::Disconnected) => {
                if !matches!(phase, Phase::Probing(..)) {
                    send(&instance.goodbye(), to);
                }
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
        let now = Instant::now();
        match phase {
            Phase::Probing(sent, due) if now >= due => {
                if sent < PROBES {
                    send(&instance.probe(), to);
                    phase = Phase::Probing(sent + 1, now + PROBE_GAP);
                } else {
                    phase = Phase::Announcing(0, now);
                }
            }
            Phase::Announcing(sent, due) if now >= due => {
                send(&instance.announcement(), to);
                phase = if sent + 1 < ANNOUNCEMENTS {
                    Phase::Announcing(sent + 1, now + ANNOUNCE_GAP)
                } else {
                    Phase::Settled
                };
            }
            _ => {}
        }
        let (n, from) = match socket.recv_from(&mut buffer) {
            Ok((n, SocketAddr::V4(from))) => (n, from),
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // An error from the network, such as an interface going down, is waited out.
            Err(_) => {
                thread::sleep(WAIT);
                continue;
            }
        };
        let Ok(message) = Message::decode(&buffer[..n]) else { continue };
        if message.response {
            if instance.conflicts(&message) {
                if !matches!(phase, Phase::Probing(..)) {
                    send(&instance.goodbye(), to);
                }
                conflicts += 1;
                instance = base.renamed(conflicts);
                if let Ok(mut name) = named.lock() {
                    name.clone_from(&instance.name);
                }
                phase = Phase::Probing(0, Instant::now());
            }
        } else if !matches!(phase, Phase::Probing(..)) {
            let legacy = from.port() != to.port();
            if let Some(response) = instance.answer(&message, legacy) {
                send(&response, if legacy { from } else { to });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> Instance {
        Instance {
            service: "_nmos-node._tcp".into(),
            name: "Test tone".into(),
            host: host_label("Studio-Mac.example.com"),
            port: 39749,
            address: Ipv4Addr::new(192, 168, 10, 21),
            txt: vec![("api_proto".into(), "http".into()), ("ver_snd".into(), "3".into())],
        }
    }

    fn of(message: &Message, kind: u16) -> Vec<&Record> {
        message.answers.iter().chain(&message.additionals).filter(|r| r.kind == kind).collect()
    }

    #[test]
    fn names_the_host_and_renames_on_conflict() {
        let i = instance();
        assert_eq!(i.host, "studio-mac");
        assert_eq!(i.full_name().to_string(), "Test tone._nmos-node._tcp.local");
        assert_eq!(i.host_name().to_string(), "studio-mac.local");
        let again = i.renamed(1);
        assert_eq!((again.name.as_str(), again.host.as_str()), ("Test tone (2)", "studio-mac-2"));
        assert_eq!(i.renamed(0), i);
        let long = Instance { name: "é".repeat(40), ..instance() }.renamed(9);
        assert!(long.name.len() <= 63 && long.name.ends_with(" (10)"), "{}", long.name);
        assert_eq!(host_label("_.local"), "host");
    }

    #[test]
    fn announces_probes_and_says_goodbye() {
        let i = instance();
        let announcement = Message::decode(&i.announcement().encode()).unwrap();
        assert!(announcement.response && announcement.authoritative && announcement.questions.is_empty());
        let ptr = of(&announcement, dns::PTR);
        assert_eq!(ptr[0].data, Data::Ptr(i.full_name()));
        assert!(!ptr[0].cache_flush, "a shared record");
        let srv = of(&announcement, dns::SRV)[0];
        assert!(srv.cache_flush && srv.ttl == 120);
        assert_eq!(srv.data, Data::Srv { priority: 0, weight: 0, port: 39749, target: i.host_name() });
        let Data::Txt(strings) = &of(&announcement, dns::TXT)[0].data else { unreachable!("TXT") };
        assert_eq!(dns::txt_pairs(strings)["ver_snd"], "3");
        assert_eq!(of(&announcement, dns::A)[0].data, Data::A(Ipv4Addr::new(192, 168, 10, 21)));
        assert!(i.goodbye().answers.iter().all(|r| r.ttl == 0));
        let probe = Message::decode(&i.probe().encode()).unwrap();
        assert!(!probe.response && probe.questions.iter().all(|q| q.unicast && q.kind == dns::ANY));
        assert_eq!(probe.questions.len(), 2);
        assert_eq!(probe.authorities.len(), 3, "its SRV, TXT and A records");
        // Its own records, heard back, are no conflict; another's for its names are.
        assert!(!i.conflicts(&announcement) && !i.conflicts(&probe));
        let mut other = Instance { port: 80, ..instance() }.announcement();
        assert!(i.conflicts(&other));
        other.answers.iter_mut().for_each(|r| r.ttl = 0);
        assert!(!i.conflicts(&other), "a goodbye is none");
        assert!(i.conflicts(&Instance { address: Ipv4Addr::new(10, 0, 0, 1), ..instance() }.announcement()));
    }

    #[test]
    fn answers_what_is_asked_with_what_comes_next() {
        let i = instance();
        let ask = |name: Name, kind| Message::query(0, vec![Question::new(name, kind)]);
        // Browsing: the pointer, with the SRV, TXT and A records as additional records.
        let browse = i.answer(&ask(i.service_name(), dns::PTR), false).unwrap();
        assert_eq!(browse.answers.len(), 1);
        assert_eq!(browse.additionals.iter().map(|r| r.kind).collect::<Vec<_>>(), [dns::SRV, dns::TXT, dns::A]);
        assert_eq!(browse.id, 0);
        // Resolving, with the address after the SRV record.
        let srv = i.answer(&ask(i.full_name(), dns::SRV), false).unwrap();
        assert_eq!((srv.answers[0].kind, srv.additionals[0].kind), (dns::SRV, dns::A));
        let a = i.answer(&ask(Name::parse("STUDIO-MAC.local"), dns::A), false).unwrap();
        assert_eq!(a.answers[0].data, Data::A(i.address));
        assert_eq!(i.answer(&ask(i.full_name(), dns::ANY), false).unwrap().answers.len(), 2);
        let types = i.answer(&ask(Name::parse(SERVICES), dns::PTR), false).unwrap();
        assert_eq!(types.answers[0].data, Data::Ptr(i.service_name()));
        // Not about it, or already known for more than half its life: no answer.
        assert_eq!(i.answer(&ask(Name::parse("_nmos-query._tcp.local"), dns::PTR), false), None);
        let mut known = ask(i.service_name(), dns::PTR);
        known.answers.push(Record::new(i.service_name(), 4000, Data::Ptr(i.full_name())));
        assert_eq!(i.answer(&known, false), None);
        known.answers[0].ttl = 1000;
        assert!(i.answer(&known, false).is_some());
        // A one-shot querier gets its identifier and questions back, and short lives.
        let mut one_shot = ask(i.service_name(), dns::PTR);
        one_shot.id = 0x2a;
        let legacy = Message::decode(&i.answer(&one_shot, true).unwrap().encode()).unwrap();
        assert_eq!((legacy.id, legacy.questions.len()), (0x2a, 1));
        assert!(legacy.records().all(|r| r.ttl <= 10 && !r.cache_flush));
        // A response asks nothing.
        assert_eq!(i.answer(&i.announcement(), false), None);
    }
}
