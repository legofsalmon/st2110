//! Finding one kind of NMOS API by DNS-SD, once, as a command that has not been told
//! where it is does: a registry's Query API (IS-04 §3) or an IS-10 Authorization Server
//! (IS-10 Discovery).
//!
//! Unicast DNS-SD comes first, in the search domains, as both specifications prefer it;
//! multicast DNS is asked only when the DNS servers know of none ("Unicast vs Multicast
//! DNS-SD"), for a few seconds.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use crate::dns::{self, Name, Question, Record};
use crate::dnssd::Cache;
use crate::net::{MDNS, Mdns, interfaces};
use crate::nmos::{Api, ApiKind, MDNS as BY_MDNS};
use crate::{browse_unicast, resolv};

/// Where and how long to look.
#[derive(Clone, Debug)]
pub struct Look {
    /// The DNS servers to ask: the system's when empty.
    pub dns_servers: Vec<SocketAddr>,
    /// The domains to ask in: the system's search domains when `None`.
    pub domains: Option<Vec<String>>,
    /// Whether to ask DNS servers at all.
    pub dns: bool,
    /// Where to ask by multicast DNS: its group, by default, or a responder's own
    /// address; `None` to ask nothing.
    pub mdns: Option<SocketAddrV4>,
    /// How long a DNS server may take to answer.
    pub timeout: Duration,
    /// How long to listen for multicast DNS answers, at most.
    pub listen: Duration,
}

impl Default for Look {
    fn default() -> Self {
        Self {
            dns_servers: Vec::new(),
            domains: None,
            dns: true,
            mdns: Some(MDNS),
            timeout: Duration::from_secs(2),
            listen: Duration::from_secs(3),
        }
    }
}

/// What a look found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seen {
    /// The APIs found, in no order: [`crate::nmos::by_preference`] orders registries,
    /// [`by_priority`] Authorization Servers.
    pub apis: Vec<Api>,
    /// Where it looked, in a few words each, such as `DNS in studio.example`.
    pub looked: Vec<String>,
    /// What could not be asked, such as a DNS server that did not answer.
    pub problems: Vec<String>,
}

/// Looks for the APIs of `kind`: by unicast DNS-SD in each domain, then, when that
/// finds none, by multicast DNS until a little after the first answer, or
/// [`Look::listen`].
pub fn find(kind: ApiKind, look: &Look) -> Seen {
    let mut seen = Seen::default();
    if look.dns {
        let (system_servers, system_domains) = resolv::system();
        let servers = if look.dns_servers.is_empty() { system_servers } else { look.dns_servers.clone() };
        let domains = look.domains.clone().unwrap_or(system_domains);
        for domain in &domains {
            if servers.is_empty() {
                break;
            }
            seen.looked.push(format!("DNS in {domain}"));
            let service = Name::parse(&format!("{}.{domain}", kind.service()));
            match browse_unicast(&servers, &service, look.timeout) {
                Ok(services) => {
                    let by = format!("DNS in {domain}");
                    seen.apis.extend(services.iter().filter_map(|s| Api::from_service(s, kind, &by)));
                }
                Err(e) => seen.problems.push(format!("DNS in {domain}: {e}")),
            }
        }
    }
    if !seen.apis.is_empty() {
        return seen;
    }
    if let Some(to) = look.mdns {
        seen.looked.push("multicast DNS".into());
        match ask_mdns(kind, to, look.listen) {
            Ok(apis) => seen.apis = apis,
            Err(e) => seen.problems.push(format!("multicast DNS: {e}")),
        }
    }
    seen
}

/// Asks by multicast DNS for the instances of `kind` and the records each one lacks,
/// a second apart, until half a second after the last new API, or `listen`.
fn ask_mdns(kind: ApiKind, to: SocketAddrV4, listen: Duration) -> std::io::Result<Vec<Api>> {
    let ports: Vec<Ipv4Addr> = interfaces().into_iter().map(|i| i.address).collect();
    let mdns = Mdns::open(to, &ports)?;
    let service = Name::parse(&format!("{}.local", kind.service()));
    let names = [service.clone()];
    let start = Instant::now();
    let deadline = start + listen;
    let mut cache = Cache::default();
    let mut buffer = vec![0u8; 9000];
    let mut asked: HashMap<Question, Instant> = HashMap::new();
    let mut found: Vec<Api> = Vec::new();
    let mut settled: Option<Instant> = None;
    // Responders answer a one-shot query with records that live 10 s at most (RFC 6762
    // §6.7); they are kept for this look.
    let floor = listen;
    while Instant::now() < deadline && settled.is_none_or(|at| Instant::now() < at) {
        let now = Instant::now();
        let mut due: Vec<Question> = cache.wanted(&names);
        due.push(Question::new(service.clone(), dns::PTR));
        due.retain(|q| asked.get(q).is_none_or(|at| now.duration_since(*at) >= Duration::from_secs(1)));
        for question in &due {
            asked.insert(question.clone(), now);
        }
        mdns.ask(&due)?;
        if let Some(message) = mdns.receive(&mut buffer)? {
            let heard = Instant::now();
            let ours = |r: &&Record| matches!(r.kind, dns::PTR | dns::SRV | dns::TXT) && r.name.ends_with(&service);
            message.records().filter(ours).for_each(|r| cache.add(r.clone(), heard, floor));
            let hosts = cache.hosts();
            message.records().filter(|r| r.kind == dns::A && hosts.contains(&r.name)).for_each(|r| {
                cache.add(r.clone(), heard, floor);
            });
        }
        let apis: Vec<Api> = cache
            .instances(&service)
            .iter()
            .filter_map(|i| cache.resolve(i))
            .filter_map(|s| Api::from_service(&s, kind, BY_MDNS))
            .collect();
        if apis.len() > found.len() {
            found = apis;
            settled = Some(Instant::now() + Duration::from_millis(500));
        }
    }
    Ok(found)
}

/// Authorization Servers or System APIs in the order to try them (IS-10 Discovery and
/// IS-09 Discovery, `pri`): those in use before those for development, the lowest
/// priority first. As for registries, those found by multicast DNS are left out where
/// unicast DNS-SD found any. Registries and Nodes are left out.
pub fn by_priority<'a>(apis: impl IntoIterator<Item = &'a Api>) -> Vec<&'a Api> {
    let mut servers: Vec<&Api> =
        apis.into_iter().filter(|a| matches!(a.kind, ApiKind::Auth | ApiKind::System)).collect();
    if servers.iter().any(|a| a.by != BY_MDNS) {
        servers.retain(|a| a.by != BY_MDNS);
    }
    servers.sort_by_key(|a| (a.priority.unwrap_or(99), a.url.clone()));
    servers.dedup_by(|a, b| a.url == b.url);
    servers
}
