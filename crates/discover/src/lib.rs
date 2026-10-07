//! Finds the ST 2110 streams on a network, as a monitor or a controller does: from the
//! SDP files that senders announce by SAP, and from the Senders that NMOS lists, read
//! from a registry that DNS-SD finds or, where it finds none, from each Node peer to
//! peer.
//!
//! [`Discovery`] looks on threads of its own, and its [`List`] says what it has found so
//! far: each stream with its SDP file, what it carries, and how it was found.
//!
//! - **SAP** (RFC 2974): it joins the groups that announcements go to, 239.255.255.255
//!   (where AES67 devices announce) and 224.2.127.254, on port 9875, and keeps each
//!   session until it is deleted or long unheard.
//! - **NMOS by DNS-SD** (IS-04 §3): it browses for registries' Query APIs
//!   (`_nmos-query._tcp`) and Nodes' Node APIs (`_nmos-node._tcp`) by multicast DNS on
//!   each port, and for Query APIs by unicast DNS in the system's search domains. It
//!   reads the registry a controller would choose: one that asks for no authorization,
//!   in use rather than for development, of the highest priority.
//! - **NMOS peer to peer**: where no registry answers, it reads each Node it found, and
//!   reads it again when the version counters it advertises change.
//!
//! A stream that SAP and NMOS both describe, going to the same destinations, is listed
//! once, with both.
//!
//! ```no_run
//! use std::time::Duration;
//! use st2110_discover::{Discovery, Options};
//!
//! let discovery = Discovery::start(Options::default(), || {});
//! std::thread::sleep(Duration::from_secs(5));
//! for stream in discovery.list().streams {
//!     println!("{}: {}, to {}", stream.name, stream.format(), stream.destinations().join(" and "));
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dns;
pub mod dnssd;
pub mod net;
pub mod nmos;
pub mod resolv;
pub mod sap;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use st2110_nmos::client;
use st2110_sdp::Stream;

use crate::dns::{Name, Question, Record};
use crate::dnssd::{Cache, Service};
use crate::net::{Mdns, TICK};
use crate::nmos::{Api, ApiKind, Reader, Sender};
use crate::sap::Sessions;

pub use crate::net::{Announcer, Interface, MDNS, interfaces};

/// How often a querier asks by multicast DNS once it has asked a few times; one that
/// asks from a port of its own hears no announcements, so asks more often.
const MDNS_EVERY: Duration = Duration::from_secs(30);
const ONE_SHOT_EVERY: Duration = Duration::from_secs(5);

/// How often the DNS servers are browsed again.
const DNS_EVERY: Duration = Duration::from_secs(60);

/// How many Nodes are read at once, peer to peer.
const PARALLEL_NODES: usize = 16;

/// Where and how to look.
#[derive(Clone, Debug)]
pub struct Options {
    /// The addresses of the ports to look on: every port that is up when empty.
    pub interfaces: Vec<Ipv4Addr>,
    /// Where to hear SAP: the groups announcements go to, by default; none to hear none.
    /// A unicast address is listened on as it is.
    pub sap: Vec<SocketAddrV4>,
    /// Whether to look for NMOS Senders.
    pub nmos: bool,
    /// A registry's Query API to read, rather than finding one by DNS-SD.
    pub registry: Option<String>,
    /// Where to ask by multicast DNS: its group, by default; `None` to ask nothing.
    pub mdns: Option<SocketAddrV4>,
    /// Whether to browse DNS servers for registries by unicast DNS-SD.
    pub dns: bool,
    /// The DNS servers to browse: the system's when empty.
    pub dns_servers: Vec<SocketAddr>,
    /// The domains to browse: the system's search domains when `None`.
    pub domains: Option<Vec<String>>,
    /// How often to read the registry, or the Nodes, again.
    pub refresh: Duration,
    /// How long a request to a DNS server, a registry or a Node may take.
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            sap: vec![sap::ADMIN_LOCAL, sap::GLOBAL],
            nmos: true,
            registry: None,
            mdns: Some(MDNS),
            dns: true,
            dns_servers: Vec::new(),
            domains: None,
            refresh: Duration::from_secs(15),
            timeout: Duration::from_secs(5),
        }
    }
}

/// A stream found on the network.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Found {
    /// Its name: the NMOS Sender's label, or else the session name in its SDP file.
    pub name: String,
    /// Its SDP file, when there is one to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    /// The media sections of its SDP file, as `st2110 lint` reads them.
    pub streams: Vec<Stream>,
    /// Whether its sender says it is sending: an NMOS Sender's `subscription.active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Whether only SAP announced it, and not for three times as long as between its
    /// announcements: its sender may have stopped.
    pub stale: bool,
    /// Why there is no SDP file to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// How it was found, NMOS Senders first.
    pub by: Vec<Origin>,
}

/// How a stream was found.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "by", rename_all = "kebab-case")]
pub enum Origin {
    /// Announced by SAP.
    Sap {
        /// The announcer's address.
        announcer: IpAddr,
        /// Seconds since it was last heard.
        heard_s: f64,
        /// Seconds between its last two announcements.
        #[serde(skip_serializing_if = "Option::is_none")]
        interval_s: Option<f64>,
    },
    /// An NMOS Sender.
    Nmos {
        /// Its `id`.
        id: String,
        /// Its `label`.
        label: String,
        /// The label of its Node.
        #[serde(skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        /// The label of its Device.
        #[serde(skip_serializing_if = "Option::is_none")]
        device: Option<String>,
        /// The API it was read from: a registry's Query API, or its Node's Node API.
        api: String,
        /// Whether it was read from its Node, peer to peer.
        peer_to_peer: bool,
    },
}

impl Origin {
    /// How it was found, in a few words: `SAP from 192.168.10.30`, `NMOS Node Camera 1`.
    pub fn describe(&self) -> String {
        match self {
            Self::Sap { announcer, .. } => format!("SAP from {announcer}"),
            Self::Nmos { node: Some(node), .. } if !node.trim().is_empty() => format!("NMOS Node {node}"),
            Self::Nmos { api, .. } => format!("NMOS at {api}"),
        }
    }
}

impl Found {
    /// What it carries: its first stream's standard and format, such as
    /// `ST 2110-30, L24 48 kHz, 8 channels, 1 ms`.
    pub fn format(&self) -> String {
        self.streams.first().map_or_else(String::new, |s| format!("{}, {}", s.essence.standard(), s.summary))
    }

    /// Where each media section's packets go: `239.69.83.67:5004`.
    pub fn destinations(&self) -> Vec<String> {
        self.streams.iter().filter_map(|s| Some(format!("{}:{}", s.destination.as_deref()?, s.port?))).collect()
    }

    /// What names it across ways of finding it: where its packets go, from where.
    fn key(&self) -> Option<String> {
        let mut legs: Vec<String> = self
            .streams
            .iter()
            .filter_map(|s| {
                let at = format!("{}:{}", s.destination.as_deref()?, s.port?);
                Some(s.source.as_ref().map_or_else(|| at.clone(), |source| format!("{at} from {source}")))
            })
            .collect();
        legs.sort();
        (!legs.is_empty()).then(|| legs.join(", "))
    }
}

/// What has been found so far.
#[derive(Clone, Debug, Default, Serialize)]
pub struct List {
    /// The streams, in name order.
    pub streams: Vec<Found>,
    /// The NMOS APIs found: registries' Query APIs and Nodes' Node APIs.
    pub apis: Vec<Api>,
    /// The registry the NMOS Senders were read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Whether the NMOS Senders were read from each Node, peer to peer.
    pub peer_to_peer: bool,
    /// Where it looks.
    pub looking: Vec<String>,
    /// What has gone wrong.
    pub notes: Vec<String>,
    /// Whether it is reading a registry or the Nodes now, or has found one it has yet to
    /// read.
    #[serde(skip)]
    pub busy: bool,
}

#[derive(Default)]
struct State {
    /// Counts the changes to what the list shows.
    generation: u64,
    /// Counts the changes to the NMOS APIs found.
    apis_changed: u64,
    /// The count of changes when the NMOS APIs were last taken to be read.
    apis_read: u64,
    /// Counts the times a fresh look was asked for.
    refreshes: u64,
    sap: Sessions,
    mdns_apis: Vec<Api>,
    dns_apis: Vec<Api>,
    senders: Vec<Sender>,
    registry: Option<String>,
    peer_to_peer: bool,
    busy: bool,
    /// Where it looks, by part, in the order to say so.
    looking: BTreeMap<&'static str, String>,
    /// What has gone wrong, by what it is about.
    notes: BTreeMap<String, String>,
}

struct Shared {
    state: Mutex<State>,
    /// Signalled when the NMOS APIs found change, a fresh look is asked for, or it stops.
    changed: Condvar,
    stop: AtomicBool,
    wake: Box<dyn Fn() + Send + Sync>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Changes the state with `change`, which gives whether the list changed, and if it
    /// did says so to whoever shows it.
    fn update(&self, change: impl FnOnce(&mut State) -> bool) {
        let changed = {
            let mut state = self.lock();
            let changed = change(&mut state);
            if changed {
                state.generation += 1;
            }
            changed
        };
        if changed {
            self.changed.notify_all();
            (self.wake)();
        }
    }

    /// Notes what has gone wrong with `about`, or that nothing has, with `None`.
    fn note(&self, about: &str, note: Option<String>) {
        self.update(|s| match note {
            Some(note) => s.notes.insert(about.to_string(), note.clone()).as_ref() != Some(&note),
            None => s.notes.remove(about).is_some(),
        });
    }

    fn refreshes(&self) -> u64 {
        self.lock().refreshes
    }

    /// Waits until `ready` holds, it stops, or `most` has passed; gives whether it stopped.
    fn wait(&self, most: Duration, ready: impl Fn(&State) -> bool) -> bool {
        let deadline = Instant::now() + most;
        let mut state = self.lock();
        while !self.stopped() && !ready(&state) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            state = self.changed.wait_timeout(state, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
        }
        self.stopped()
    }
}

/// Looks for streams until it is dropped.
pub struct Discovery {
    shared: Arc<Shared>,
}

impl Discovery {
    /// Starts looking as `options` say, calling `wake` whenever the list changes. What
    /// cannot be looked at, such as a port another program holds alone, is noted in the
    /// list.
    pub fn start(options: Options, wake: impl Fn() + Send + Sync + 'static) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            stop: AtomicBool::new(false),
            wake: Box::new(wake),
        });
        // Until the first read of a registry or the Nodes, which starts at once.
        shared.lock().busy = options.nmos;
        let interfaces: Vec<Ipv4Addr> = if options.interfaces.is_empty() {
            interfaces().into_iter().map(|i| i.address).collect()
        } else {
            options.interfaces.clone()
        };
        let spawn = |name: &str, run: Box<dyn FnOnce() + Send>| {
            if let Err(e) = thread::Builder::new().name(name.into()).spawn(run) {
                shared.note(name, Some(format!("Cannot start looking: {e}")));
            }
        };
        if !options.sap.is_empty() {
            let addresses = options.sap.iter().map(ToString::to_string).collect::<Vec<_>>().join(" and ");
            match net::sap_sockets(&options.sap, &interfaces) {
                Ok(sockets) => {
                    shared.update(|s| s.looking.insert("1 sap", format!("SAP announcements to {addresses}")).is_none());
                    for socket in sockets {
                        let shared = Arc::clone(&shared);
                        spawn("sap", Box::new(move || listen_sap(&shared, &socket)));
                    }
                }
                Err(e) => shared.note("sap", Some(format!("Cannot hear SAP announcements to {addresses}: {e}"))),
            }
        }
        if options.nmos {
            match &options.registry {
                Some(url) => {
                    shared.update(|s| s.looking.insert("2 registry", format!("the NMOS registry at {url}")).is_none())
                }
                None => {
                    if let Some(to) = options.mdns {
                        match Mdns::open(to, &interfaces) {
                            Ok(mdns) => {
                                let how = if mdns.one_shot { ", from a port of its own" } else { "" };
                                let looking = format!("NMOS registries and Nodes by multicast DNS{how}");
                                shared.update(|s| s.looking.insert("3 mdns", looking).is_none());
                                let shared = Arc::clone(&shared);
                                spawn("mdns", Box::new(move || browse_mdns(&shared, &mdns)));
                            }
                            Err(e) => shared.note("mdns", Some(format!("Cannot ask by multicast DNS: {e}"))),
                        }
                    }
                    if options.dns {
                        let (system_servers, system_domains) = resolv::system();
                        let servers =
                            if options.dns_servers.is_empty() { system_servers } else { options.dns_servers.clone() };
                        let domains = options.domains.clone().unwrap_or(system_domains);
                        if !servers.is_empty() && !domains.is_empty() {
                            let looking = format!("NMOS registries by DNS-SD in {}", domains.join(", "));
                            shared.update(|s| s.looking.insert("4 dns", looking).is_none());
                            let shared = Arc::clone(&shared);
                            let timeout = options.timeout;
                            spawn("dns-sd", Box::new(move || browse_dns(&shared, &servers, &domains, timeout)));
                        }
                    }
                }
            }
            let shared_nmos = Arc::clone(&shared);
            let options = options.clone();
            spawn("nmos", Box::new(move || read_nmos(&shared_nmos, &options)));
        }
        Self { shared }
    }

    /// What has been found so far.
    pub fn list(&self) -> List {
        let state = self.shared.lock();
        let mut apis: Vec<Api> = state.mdns_apis.iter().chain(&state.dns_apis).cloned().collect();
        apis.sort();
        apis.dedup_by(|a, b| a.kind == b.kind && a.url == b.url);
        List {
            streams: assemble(&state, Instant::now()),
            apis,
            registry: state.registry.clone(),
            peer_to_peer: state.peer_to_peer,
            looking: state.looking.values().cloned().collect(),
            notes: state.notes.values().cloned().collect(),
            busy: state.busy || state.apis_read != state.apis_changed,
        }
    }

    /// A number that changes whenever the list does, apart from how long ago each SAP
    /// announcement was heard.
    pub fn generation(&self) -> u64 {
        self.shared.lock().generation
    }

    /// Asks again at once: by multicast DNS and of the DNS servers, and reads the
    /// registry or the Nodes again, with every SDP file.
    pub fn refresh(&self) {
        self.shared.update(|s| {
            s.refreshes += 1;
            false
        });
        self.shared.changed.notify_all();
    }
}

impl Drop for Discovery {
    /// Stops looking. The threads end on their own, within a tick or a request.
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.shared.changed.notify_all();
    }
}

/// Hears SAP packets on one socket until it stops.
fn listen_sap(shared: &Shared, socket: &UdpSocket) {
    let mut buffer = vec![0u8; 65_536];
    let mut expired = Instant::now();
    let mut unreadable = 0;
    while !shared.stopped() {
        match socket.recv_from(&mut buffer) {
            Ok((n, _)) => match sap::parse(&buffer[..n]) {
                Ok(packet) => shared.update(|s| s.sap.heard(&packet, Instant::now())),
                Err(e) => {
                    unreadable += 1;
                    let said = if unreadable == 1 { "1 SAP packet" } else { "SAP packets" };
                    shared.note("sap-unreadable", Some(format!("{said} could not be read, the last because {e}")));
                }
            },
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                shared.note("sap", Some(format!("Cannot hear SAP: {e}")));
                thread::sleep(TICK);
            }
        }
        if expired.elapsed() >= Duration::from_secs(1) {
            expired = Instant::now();
            shared.update(|s| s.sap.expire(expired));
        }
    }
}

/// The NMOS service types, as multicast DNS names them, and the API each advertises.
fn nmos_types(domain: &str) -> [(Name, ApiKind); 2] {
    [(nmos::QUERY, ApiKind::Query), (nmos::NODE, ApiKind::Node)]
        .map(|(t, k)| (Name::parse(&format!("{t}.{domain}")), k))
}

/// The APIs of the instances of `types` that the cache can resolve.
fn apis_in(cache: &Cache, types: &[(Name, ApiKind)], by: &str) -> Vec<Api> {
    let mut apis: Vec<Api> = types
        .iter()
        .flat_map(|(name, kind)| {
            cache
                .instances(name)
                .into_iter()
                .filter_map(|i| cache.resolve(&i))
                .filter_map(|s| Api::from_service(&s, *kind, by))
        })
        .collect();
    apis.sort();
    apis.dedup();
    apis
}

/// Browses for NMOS APIs by multicast DNS until it stops: asks after 1 s, 2 s, 4 s and
/// so on, up to every 30 s (RFC 6762 §5.2), and asks at once for the records that each
/// instance it hears of still lacks.
fn browse_mdns(shared: &Shared, mdns: &Mdns) {
    let types = nmos_types("local");
    let names: Vec<Name> = types.iter().map(|(n, _)| n.clone()).collect();
    let browse: Vec<Question> = names.iter().map(|n| Question::new(n.clone(), dns::PTR)).collect();
    // Responders answer a one-shot query with records that live 10 s at most (RFC 6762
    // §6.7), so those are kept until they are asked for again.
    let (most, floor) = if mdns.one_shot { (ONE_SHOT_EVERY, 3 * ONE_SHOT_EVERY) } else { (MDNS_EVERY, Duration::ZERO) };
    let mut cache = Cache::default();
    let mut buffer = vec![0u8; 9000];
    let (mut next, mut delay) = (Instant::now(), Duration::from_secs(1));
    // When each record still wanted was last asked for, and how long to wait before
    // asking again: a second, doubling to a minute.
    let mut asked: HashMap<Question, (Instant, Duration)> = HashMap::new();
    let mut refreshes = shared.refreshes();
    let mut found: Vec<Api> = Vec::new();
    while !shared.stopped() {
        let now = Instant::now();
        let r = shared.refreshes();
        if r != refreshes {
            (refreshes, next, delay) = (r, now, Duration::from_secs(1));
        }
        if now >= next {
            let asking = mdns.ask(&browse);
            shared.note("mdns", asking.err().map(|e| format!("Cannot ask by multicast DNS: {e}")));
            next = now + delay;
            delay = (delay * 2).min(most);
        }
        let wanted = cache.wanted(&names);
        asked.retain(|q, _| wanted.contains(q));
        let due: Vec<Question> = wanted
            .into_iter()
            .filter(|q| asked.get(q).is_none_or(|(at, gap)| now.duration_since(*at) >= *gap))
            .collect();
        if !due.is_empty() {
            for question in &due {
                let gap = asked
                    .get(question)
                    .map_or(Duration::from_secs(1), |(_, gap)| (*gap * 2).min(Duration::from_secs(60)));
                asked.insert(question.clone(), (now, gap));
            }
            let _ = mdns.ask(&due);
        }
        match mdns.receive(&mut buffer) {
            Ok(Some(message)) => {
                let heard = Instant::now();
                // Every responder on the link answers to the group; only these records are kept.
                let ours = |r: &&Record| {
                    matches!(r.kind, dns::PTR | dns::SRV | dns::TXT) && names.iter().any(|n| r.name.ends_with(n))
                };
                message.records().filter(ours).for_each(|r| cache.add(r.clone(), heard, floor));
                let hosts = cache.hosts();
                let addresses = |r: &&Record| r.kind == dns::A && hosts.contains(&r.name);
                message.records().filter(addresses).for_each(|r| cache.add(r.clone(), heard, floor));
            }
            Ok(None) => {}
            Err(e) => {
                shared.note("mdns", Some(format!("Cannot hear multicast DNS: {e}")));
                thread::sleep(TICK);
            }
        }
        cache.expire(Instant::now());
        let apis = apis_in(&cache, &types, "mDNS");
        if apis != found {
            found.clone_from(&apis);
            shared.update(|s| {
                s.mdns_apis = apis;
                s.apis_changed += 1;
                true
            });
        }
    }
}

/// Asks the first of `servers` that answers.
fn ask(servers: &[SocketAddr], question: &Question, timeout: Duration) -> Result<dns::Message, String> {
    let mut last = "no DNS server to ask".to_string();
    for server in servers {
        match net::lookup(*server, question, timeout) {
            Ok(message) => return Ok(message),
            Err(e) => last = format!("{server}: {e}"),
        }
    }
    Err(last)
}

/// Browses DNS servers for the instances of `service`, a service type in a domain, and
/// resolves each one (RFC 6763 §4).
fn browse_unicast(servers: &[SocketAddr], service: &Name, timeout: Duration) -> Result<Vec<Service>, String> {
    let now = Instant::now();
    let mut cache = Cache::default();
    // A DNS server may give a record no time to live, to be used once and not kept.
    let keep = |cache: &mut Cache, message: &dns::Message| {
        for record in message.records() {
            cache.add(Record { ttl: record.ttl.max(1), ..record.clone() }, now, Duration::ZERO);
        }
    };
    let response = ask(servers, &Question::new(service.clone(), dns::PTR), timeout)?;
    match response.rcode {
        // No such name: nothing advertised there.
        0 | 3 => keep(&mut cache, &response),
        code => return Err(format!("the DNS server answered with response code {code}")),
    }
    // Ask for what the server did not give with its answer, a round at a time.
    for _ in 0..3 {
        let wanted = cache.wanted(std::slice::from_ref(service));
        if wanted.is_empty() {
            break;
        }
        for question in &wanted {
            if let Ok(message) = ask(servers, question, timeout) {
                keep(&mut cache, &message);
            }
        }
    }
    Ok(cache.instances(service).iter().filter_map(|i| cache.resolve(i)).collect())
}

/// Browses DNS servers for registries in each domain, every minute or when asked to,
/// until it stops.
fn browse_dns(shared: &Shared, servers: &[SocketAddr], domains: &[String], timeout: Duration) {
    loop {
        let refreshes = shared.refreshes();
        let mut apis = Vec::new();
        let mut problems = Vec::new();
        for domain in domains {
            let service = Name::parse(&format!("{}.{domain}", nmos::QUERY));
            match browse_unicast(servers, &service, timeout) {
                Ok(services) => {
                    let by = format!("DNS in {domain}");
                    apis.extend(services.iter().filter_map(|s| Api::from_service(s, ApiKind::Query, &by)));
                }
                Err(e) => problems.push(format!("{domain}: {e}")),
            }
        }
        apis.sort();
        apis.dedup();
        let note =
            (!problems.is_empty()).then(|| format!("Cannot browse DNS for registries in {}", problems.join("; ")));
        shared.note("dns", note);
        shared.update(|s| {
            if s.dns_apis == apis {
                return false;
            }
            s.dns_apis = apis;
            s.apis_changed += 1;
            true
        });
        if shared.wait(DNS_EVERY, |s| s.refreshes != refreshes) {
            return;
        }
    }
}

/// One Node's last read, peer to peer: the counters it advertised then, when, and its
/// Senders.
struct NodeRead {
    counters: BTreeMap<String, String>,
    at: Instant,
    senders: Vec<Sender>,
}

/// What reading an API gives: the reader to keep for next time, unless reading failed,
/// and the Senders, or why there are none.
type Outcome = (Option<Reader>, Result<Vec<Sender>, String>);

/// Reads one API with the reader kept for it, connecting first where there is none.
/// Gives the reader back, unless reading failed, so that the next read connects again.
fn read_api(reader: Option<Reader>, api: &Api, options: &client::Options, afresh: bool) -> Outcome {
    let mut reader = match reader {
        Some(reader) => reader,
        None => match Reader::connect(api, options) {
            Ok(reader) => reader,
            Err(e) => return (None, Err(e.to_string())),
        },
    };
    match reader.read(afresh) {
        Ok(senders) => (Some(reader), Ok(senders)),
        Err(e) => (None, Err(e.to_string())),
    }
}

/// Reads the NMOS Senders whenever the APIs found change, a fresh look is asked for, or
/// `options.refresh` has passed, until it stops: from the registry a controller would
/// choose or, where none answers, from every Node.
fn read_nmos(shared: &Shared, options: &Options) {
    let http = client::Options {
        timeout: options.timeout,
        // A proxy for the web is no way to the devices on this network.
        env_proxy: false,
        ..client::Options::default()
    };
    let mut readers: HashMap<String, Reader> = HashMap::new();
    let mut nodes: HashMap<String, NodeRead> = HashMap::new();
    let (mut seen_apis, mut seen_refreshes) = (0, 0);
    let mut last: Option<Instant> = None;
    loop {
        let due = |last: Option<Instant>| last.is_none_or(|t| t.elapsed() >= options.refresh);
        if shared.wait(TICK.max(options.refresh), |s| {
            due(last) || s.apis_changed != seen_apis || s.refreshes != seen_refreshes
        }) {
            return;
        }
        let (apis, afresh) = {
            let mut state = shared.lock();
            let afresh = state.refreshes != seen_refreshes;
            (seen_apis, seen_refreshes) = (state.apis_changed, state.refreshes);
            (state.apis_read, state.busy) = (state.apis_changed, true);
            let apis: Vec<Api> = match &options.registry {
                Some(url) => vec![Api::given(url)],
                None => state.mdns_apis.iter().chain(&state.dns_apis).cloned().collect(),
            };
            (apis, afresh)
        };
        let timed = due(last) || afresh;
        let mut notes: BTreeMap<String, String> = BTreeMap::new();
        let mut read: Option<(String, Vec<Sender>)> = None;
        for api in nmos::by_preference(&apis) {
            let (reader, result) = read_api(readers.remove(&api.url), api, &http, afresh);
            match result {
                Ok(senders) => {
                    let base = reader.as_ref().map_or_else(|| api.url.clone(), |r| r.base().to_string());
                    readers.extend(reader.map(|r| (api.url.clone(), r)));
                    read = Some((base, senders));
                    break;
                }
                Err(e) => {
                    _ = notes.insert(api.url.clone(), format!("Cannot read the NMOS registry at {}: {e}", api.url))
                }
            }
        }
        let (registry, senders, peer_to_peer) = match read {
            Some((registry, senders)) => {
                nodes.clear();
                (Some(registry), senders, false)
            }
            None => {
                let found: Vec<&Api> = apis.iter().filter(|a| a.kind == ApiKind::Node && a.readable()).collect();
                nodes.retain(|url, _| found.iter().any(|a| &a.url == url));
                let stale: Vec<&Api> = found
                    .iter()
                    .copied()
                    .filter(|a| timed || nodes.get(&a.url).is_none_or(|n| n.counters != a.counters))
                    .collect();
                for batch in stale.chunks(PARALLEL_NODES) {
                    let results: Vec<(&Api, Outcome)> = thread::scope(|scope| {
                        let handles: Vec<_> = batch
                            .iter()
                            .map(|api| {
                                let reader = readers.remove(&api.url);
                                let http = &http;
                                scope.spawn(move || (*api, read_api(reader, api, http, afresh)))
                            })
                            .collect();
                        handles.into_iter().filter_map(|h| h.join().ok()).collect()
                    });
                    for (api, (reader, result)) in results {
                        readers.extend(reader.map(|r| (api.url.clone(), r)));
                        match result {
                            Ok(senders) => {
                                let read = NodeRead { counters: api.counters.clone(), at: Instant::now(), senders };
                                nodes.insert(api.url.clone(), read);
                            }
                            Err(e) => {
                                nodes.remove(&api.url);
                                notes.insert(
                                    api.url.clone(),
                                    format!("Cannot read the NMOS Node {} at {}: {e}", api.name, api.url),
                                );
                            }
                        }
                    }
                }
                let mut senders: Vec<Sender> = Vec::new();
                let mut by_age: Vec<&NodeRead> = nodes.values().collect();
                by_age.sort_by_key(|n| n.at);
                by_age.iter().for_each(|n| senders.extend(n.senders.iter().cloned()));
                let peer_to_peer = !nodes.is_empty();
                (None, senders, peer_to_peer)
            }
        };
        readers.retain(|url, _| apis.iter().any(|a| &a.url == url));
        shared.update(|s| {
            let notes_before = s.notes.clone();
            s.notes.retain(|k, _| !k.starts_with("nmos "));
            s.notes.extend(notes.into_iter().map(|(url, note)| (format!("nmos {url}"), note)));
            let changed = s.senders != senders
                || s.registry != registry
                || s.peer_to_peer != peer_to_peer
                || s.notes != notes_before;
            (s.senders, s.registry, s.peer_to_peer, s.busy) = (senders, registry, peer_to_peer, false);
            changed
        });
        last = Some(Instant::now());
    }
}

/// The session name an SDP file gives, if it gives one.
fn session_name(sdp: &str) -> Option<String> {
    let name = sdp.lines().find_map(|l| l.trim().strip_prefix("s="))?.trim();
    (!name.is_empty() && name != "-").then(|| name.to_string())
}

/// Puts a stream in the list, or adds how it was found to the one that goes to the same
/// destinations.
fn merge(found: &mut Vec<(String, Found)>, key: String, item: Found) {
    match found.iter_mut().find(|(k, _)| *k == key) {
        Some((_, f)) => {
            f.by.extend(item.by);
            f.stale &= item.stale;
            f.active = f.active.or(item.active);
            if f.sdp.is_none() {
                (f.sdp, f.streams, f.problem) = (item.sdp, item.streams, item.problem);
            }
        }
        None => found.push((key, item)),
    }
}

/// The streams found, in name order.
fn assemble(state: &State, now: Instant) -> Vec<Found> {
    let mut found: Vec<(String, Found)> = Vec::new();
    for sender in &state.senders {
        let (sdp, problem) = match &sender.sdp {
            Ok(sdp) => (Some(sdp.clone()), None),
            Err(e) => (None, Some(e.clone())),
        };
        let streams = sdp.as_deref().map(|s| st2110_sdp::lint(s).streams).unwrap_or_default();
        let name = match sender.label.trim() {
            "" => sdp.as_deref().and_then(session_name).unwrap_or_else(|| sender.id.clone()),
            label => label.to_string(),
        };
        let origin = Origin::Nmos {
            id: sender.id.clone(),
            label: sender.label.clone(),
            node: sender.node.clone(),
            device: sender.device.clone(),
            api: sender.api.clone(),
            peer_to_peer: sender.peer_to_peer,
        };
        let item = Found { name, sdp, streams, active: sender.active, stale: false, problem, by: vec![origin] };
        let key = item.key().unwrap_or_else(|| format!("nmos {}", sender.id));
        merge(&mut found, key, item);
    }
    for (id, session) in state.sap.iter() {
        let streams = st2110_sdp::lint(&session.sdp).streams;
        let origin = Origin::Sap {
            announcer: session.origin,
            heard_s: now.saturating_duration_since(session.last).as_secs_f64(),
            interval_s: session.interval.map(|i| i.as_secs_f64()),
        };
        let mut item = Found {
            name: session_name(&session.sdp).unwrap_or_default(),
            sdp: Some(session.sdp.clone()),
            streams,
            active: None,
            stale: session.stale(now),
            problem: None,
            by: vec![origin],
        };
        if item.name.is_empty() {
            item.name =
                item.destinations().first().cloned().unwrap_or_else(|| format!("announced by {}", session.origin));
        }
        let key = item.key().unwrap_or_else(|| format!("sap {id}"));
        merge(&mut found, key, item);
    }
    found.sort_by_cached_key(|(key, f)| (f.name.to_lowercase(), key.clone()));
    found.into_iter().map(|(_, f)| f).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIDEO: &str = "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=CAM 1 video\r\nt=0 0\r\n\
        m=video 5004 RTP/AVP 96\r\nc=IN IP4 239.10.10.1/32\r\n\
        a=source-filter: incl IN IP4 239.10.10.1 192.168.10.21\r\na=rtpmap:96 raw/90000\r\n\
        a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; exactframerate=50; depth=10; TCS=SDR; \
        colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN\r\n\
        a=ts-refclk:ptp=IEEE1588-2008:traceable\r\na=mediaclk:direct=0\r\n";

    fn sender(id: &str, label: &str, sdp: Result<&str, &str>) -> Sender {
        Sender {
            id: id.into(),
            label: label.into(),
            node: Some("Camera 1".into()),
            device: None,
            active: Some(true),
            sdp: sdp.map(str::to_string).map_err(str::to_string),
            api: "http://192.168.10.2/x-nmos/query/v1.3/".into(),
            peer_to_peer: false,
        }
    }

    #[test]
    fn lists_a_stream_that_sap_and_nmos_both_describe_once() {
        let now = Instant::now();
        let senders =
            vec![sender("5e0d0001", "CAM 1 video", Ok(VIDEO)), sender("5e0d0003", "", Err("it publishes no SDP file"))];
        let mut state = State { senders, ..State::default() };
        let announced = sap::parse(&sap::packet(Ipv4Addr::new(192, 168, 10, 21), VIDEO, false)).unwrap();
        state.sap.heard(&announced, now);
        // Another session from the same announcer, with no name of its own.
        let other =
            VIDEO.replace("o=- 1 1", "o=- 2 1").replace("239.10.10.1", "239.10.10.9").replace("s=CAM 1 video", "s=-");
        state.sap.heard(&sap::parse(&sap::packet(Ipv4Addr::new(192, 168, 10, 21), &other, false)).unwrap(), now);
        let list = assemble(&state, now + Duration::from_secs(2));
        let names: Vec<&str> = list.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["239.10.10.9:5004", "5e0d0003", "CAM 1 video"]);
        let both = &list[2];
        assert_eq!(both.by.len(), 2);
        assert_eq!(both.by[0].describe(), "NMOS Node Camera 1");
        assert_eq!(both.by[1].describe(), "SAP from 192.168.10.21");
        assert!(matches!(both.by[1], Origin::Sap { heard_s, .. } if (heard_s - 2.0).abs() < 1e-9));
        assert_eq!((both.active, both.stale), (Some(true), false));
        assert_eq!(
            both.format(),
            "ST 2110-20, 1920x1080 progressive, 50 fps, YCbCr-4:2:2 10-bit, BT709 SDR, 2110GPM, 2110TPN, 2.07 Gb/s"
        );
        assert_eq!(both.destinations(), ["239.10.10.1:5004"]);
        let missing = &list[1];
        assert_eq!((missing.sdp.as_deref(), missing.problem.as_deref()), (None, Some("it publishes no SDP file")));
        // Unheard for long enough, a SAP-only stream goes stale.
        assert!(assemble(&state, now + Duration::from_secs(91))[0].stale);
        assert!(!assemble(&state, now + Duration::from_secs(91))[2].stale, "NMOS still lists it");
    }
}
