//! NMOS APIs found by DNS-SD, as IS-04 advertises them, and the Senders read from them:
//! from a registry's Query API, or peer to peer from each Node's Node API where no
//! registry is found.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use serde_json::Value;
use st2110_nmos::client::{self, NodeClient, QueryClient};
use st2110_nmos::{Kind, Manifest, Snapshot, routing};

use crate::dnssd::Service;

/// The service type registries advertise their Query API under.
pub const QUERY: &str = "_nmos-query._tcp";

/// The service type Nodes advertise their Node API under.
pub const NODE: &str = "_nmos-node._tcp";

/// The service type IS-10 Authorization Servers advertise themselves under.
pub const AUTH: &str = "_nmos-auth._tcp";

/// Registries with a priority of 100 or more are for development (IS-04 §3).
const DEVELOPMENT: u32 = 100;

/// Which API a service offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiKind {
    /// A registry's Query API.
    Query,
    /// A Node's Node API.
    Node,
    /// An IS-10 Authorization Server.
    Auth,
}

impl ApiKind {
    /// The DNS-SD service type it is advertised under.
    pub fn service(self) -> &'static str {
        match self {
            Self::Query => QUERY,
            Self::Node => NODE,
            Self::Auth => AUTH,
        }
    }
}

/// An NMOS API, found by DNS-SD or given.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Api {
    /// Which API it is.
    pub kind: ApiKind,
    /// Its service instance's name, such as `Camera 1`.
    pub name: String,
    /// Where it is: the scheme, host and port, such as `http://192.168.10.21:80`.
    pub url: String,
    /// The IS-04 versions it offers, from `api_ver`.
    pub versions: Vec<String>,
    /// A registry's priority, from `pri`: the lowest is used first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Whether it asks for IS-10 authorization, from `api_auth`.
    pub auth: bool,
    /// How it was found: `mDNS`, `DNS in studio.example`, or `given`.
    pub by: String,
    /// The version counters a Node advertises when it is not registered (`ver_slf`,
    /// `ver_snd` and the rest), which change when its resources do.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, String>,
    /// An Authorization Server's `api_selector`: the path of its issuer identifier,
    /// without the slashes at either end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

impl Api {
    /// The API a DNS-SD service advertises, once an address for it is known: over HTTP
    /// at the host's lowest IPv4 address, or over HTTPS at its name, which its
    /// certificate names.
    pub fn from_service(service: &Service, kind: ApiKind, by: &str) -> Option<Self> {
        let proto = service.txt.get("api_proto").map_or("http".to_string(), |p| p.trim().to_ascii_lowercase());
        let host = match proto.as_str() {
            "http" => service.addresses.first()?.to_string(),
            "https" => service.host.to_string(),
            _ => return None,
        };
        let versions = service
            .txt
            .get("api_ver")
            .map_or_else(Vec::new, |v| v.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect());
        Some(Self {
            kind,
            name: service.instance.clone(),
            url: format!("{proto}://{host}:{}", service.port),
            versions,
            priority: service.txt.get("pri").and_then(|p| p.trim().parse().ok()),
            auth: service.txt.get("api_auth").is_some_and(|a| a.trim().eq_ignore_ascii_case("true")),
            by: by.to_string(),
            counters: service
                .txt
                .iter()
                .filter(|(k, _)| k.starts_with("ver_"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            selector: service
                .txt
                .get("api_selector")
                .map(|s| s.trim().trim_matches('/').to_string())
                .filter(|s| !s.is_empty()),
        })
    }

    /// An Authorization Server's issuer URL, from its address and `api_selector`, as
    /// IS-10 Discovery forms its metadata URL from them.
    pub fn issuer(&self) -> String {
        match &self.selector {
            Some(path) => format!("{}/{path}/", self.url),
            None => format!("{}/", self.url),
        }
    }

    /// A registry named on the command line or in the app, rather than found.
    pub fn given(url: &str) -> Self {
        Self {
            kind: ApiKind::Query,
            name: url.to_string(),
            url: url.to_string(),
            versions: Vec::new(),
            priority: None,
            auth: false,
            by: "given".into(),
            counters: BTreeMap::new(),
            selector: None,
        }
    }

    /// Whether it offers an IS-04 version this reads: v1.0 to v1.3. One that says
    /// nothing is tried.
    pub fn readable(&self) -> bool {
        self.versions.is_empty()
            || self.versions.iter().any(|v| matches!(v.as_str(), "v1.0" | "v1.1" | "v1.2" | "v1.3"))
    }
}

/// How [`Api::by`] names an API found by multicast DNS.
pub const MDNS: &str = "mDNS";

/// The registries in the order to try them, as IS-04's discovery procedure has a
/// controller choose. Where unicast DNS-SD found any, those found by multicast DNS are
/// left out ("Unicast vs Multicast DNS-SD"). Then those that ask for no authorization,
/// which this cannot give, come first; then those in use before those for development;
/// then by priority, the lowest first, and at random among equals (step 4). The random
/// order holds for the life of the program, so that it stays with one registry.
pub fn by_preference<'a>(apis: impl IntoIterator<Item = &'a Api>) -> Vec<&'a Api> {
    by_preference_given(apis, false)
}

/// The registries in the order to try them, as [`by_preference`] has it, for a client
/// that can give an IS-10 token when `authorized`: then one that asks for authorization
/// is as good as one that does not.
pub fn by_preference_given<'a>(apis: impl IntoIterator<Item = &'a Api>, authorized: bool) -> Vec<&'a Api> {
    use std::hash::BuildHasher;
    static SHUFFLE: std::sync::OnceLock<std::hash::RandomState> = std::sync::OnceLock::new();
    let shuffle = SHUFFLE.get_or_init(std::hash::RandomState::new);
    let mut registries: Vec<&Api> = apis.into_iter().filter(|a| a.kind == ApiKind::Query && a.readable()).collect();
    if registries.iter().any(|a| a.by != MDNS) {
        registries.retain(|a| a.by != MDNS);
    }
    registries.sort_by_key(|a| {
        let priority = a.priority.unwrap_or(DEVELOPMENT - 1);
        (a.auth && !authorized, priority >= DEVELOPMENT, priority, shuffle.hash_one(&a.url), a.url.clone())
    });
    let mut seen = std::collections::HashSet::new();
    registries.retain(|a| seen.insert(a.url.clone()));
    registries
}

/// A Sender read from an NMOS API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sender {
    /// Its `id`.
    pub id: String,
    /// Its `label`.
    pub label: String,
    /// The label of its Node.
    pub node: Option<String>,
    /// The label of its Device.
    pub device: Option<String>,
    /// Whether it is sending; `None` for a Sender from before IS-04 v1.2.
    pub active: Option<bool>,
    /// Its SDP file, or why there is none to read.
    pub sdp: Result<String, String>,
    /// Where it was read: the registry's Query API, or its Node's Node API.
    pub api: String,
    /// Whether it was read from its Node, peer to peer.
    pub peer_to_peer: bool,
}

/// A client for either API.
enum Client {
    Query(QueryClient),
    Node(NodeClient),
}

impl Client {
    fn list(&self, kind: Kind) -> Result<Vec<Value>, client::Error> {
        match self {
            Self::Query(c) => c.list(kind),
            Self::Node(c) => c.list(kind),
        }
    }

    fn manifests(&self, hrefs: &[&str]) -> Vec<Manifest> {
        match self {
            Self::Query(c) => c.manifests(hrefs),
            Self::Node(c) => c.manifests(hrefs),
        }
    }

    fn base(&self) -> &str {
        match self {
            Self::Query(c) => c.base(),
            Self::Node(c) => c.base(),
        }
    }
}

/// Reads one API's Senders again and again, fetching only the SDP files of Senders that
/// are new or have changed since the last read.
pub struct Reader {
    client: Client,
    /// Each Sender's last fetch, by `id`, with the `version` and `manifest_href` it was for.
    fetched: HashMap<String, (Option<String>, String, Manifest)>,
}

impl Reader {
    /// Connects to an API, picking the IS-04 version to read.
    pub fn connect(api: &Api, options: &client::Options) -> Result<Self, client::Error> {
        let client = match api.kind {
            ApiKind::Query => Client::Query(QueryClient::connect(&api.url, options)?),
            ApiKind::Node => Client::Node(NodeClient::connect(&api.url, options)?),
            ApiKind::Auth => {
                return Err(client::Error {
                    url: api.url.clone(),
                    message: "an Authorization Server lists no Senders".into(),
                });
            }
        };
        Ok(Self { client, fetched: HashMap::new() })
    }

    /// The versioned base URL being read.
    pub fn base(&self) -> &str {
        self.client.base()
    }

    /// Reads the RTP Senders and their SDP files: every SDP file again when `afresh`.
    pub fn read(&mut self, afresh: bool) -> Result<Vec<Sender>, client::Error> {
        let snapshot = Snapshot {
            nodes: self.client.list(Kind::Node)?,
            devices: self.client.list(Kind::Device)?,
            flows: self.client.list(Kind::Flow)?,
            senders: self.client.list(Kind::Sender)?,
            ..Snapshot::default()
        };
        let versions: HashMap<&str, Option<&str>> = snapshot
            .senders
            .iter()
            .filter_map(|s| Some((s.get("id")?.as_str()?, s.get("version").and_then(Value::as_str))))
            .collect();
        let endpoints: Vec<routing::Endpoint> = routing::senders(&snapshot)
            .into_iter()
            .filter(|e| e.transport.as_deref().is_some_and(|t| t.starts_with("urn:x-nmos:transport:rtp")))
            .collect();
        let current = |e: &routing::Endpoint| {
            let (version, href) = (versions.get(e.id.as_str()).copied().flatten(), e.manifest_href.as_deref()?);
            let (was, at, manifest) = self.fetched.get(&e.id)?;
            (!afresh && was.as_deref() == version && at == href && manifest.sdp.is_some()).then_some(())
        };
        let stale: Vec<&routing::Endpoint> =
            endpoints.iter().filter(|e| is_http(e.manifest_href.as_deref()) && current(e).is_none()).collect();
        let hrefs: Vec<&str> = stale.iter().filter_map(|e| e.manifest_href.as_deref()).collect();
        for (endpoint, manifest) in stale.iter().zip(self.client.manifests(&hrefs)) {
            let version = versions.get(endpoint.id.as_str()).copied().flatten().map(str::to_string);
            let href = endpoint.manifest_href.clone().unwrap_or_default();
            self.fetched.insert(endpoint.id.clone(), (version, href, manifest));
        }
        self.fetched.retain(|id, _| endpoints.iter().any(|e| &e.id == id));
        let peer_to_peer = matches!(self.client, Client::Node(_));
        let api = self.client.base().to_string();
        Ok(endpoints
            .into_iter()
            .map(|e| {
                let sdp = match (e.manifest_href.as_deref(), self.fetched.get(&e.id)) {
                    (None, _) => Err("it publishes no SDP file".to_string()),
                    (Some(href), _) if !is_http(Some(href)) => Err(format!("its SDP file is at {href}, not on HTTP")),
                    (Some(_), Some((_, _, manifest))) => sdp_of(manifest),
                    (Some(href), None) => Err(format!("its SDP file at {href} was not fetched")),
                };
                Sender {
                    id: e.id,
                    label: e.label,
                    node: e.node,
                    device: e.device,
                    active: e.active,
                    sdp,
                    api: api.clone(),
                    peer_to_peer,
                }
            })
            .collect())
    }
}

fn is_http(href: Option<&str>) -> bool {
    href.is_some_and(|h| {
        let lower = h.trim().to_ascii_lowercase();
        lower.starts_with("http://") || lower.starts_with("https://")
    })
}

/// The SDP file a fetch returned, or why there is none.
fn sdp_of(manifest: &Manifest) -> Result<String, String> {
    match (&manifest.sdp, manifest.status, &manifest.error) {
        (Some(sdp), _, _) => Ok(sdp.clone()),
        (None, _, Some(error)) => Err(format!("its SDP file at {} cannot be fetched: {error}", manifest.url)),
        (None, Some(status), None) => Err(format!("its SDP file at {} answers HTTP {status}", manifest.url)),
        (None, None, None) => Err(format!("its SDP file at {} cannot be fetched", manifest.url)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::dns::Name;

    fn service(txt: &[(&str, &str)]) -> Service {
        Service {
            name: Name::parse("Registry A._nmos-query._tcp.local"),
            instance: "Registry A".into(),
            host: Name::parse("registry-a.local"),
            port: 8080,
            addresses: vec![Ipv4Addr::new(192, 168, 10, 2)],
            txt: txt.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn reads_what_a_service_advertises() {
        let txt = [("api_proto", "http"), ("api_ver", "v1.2, v1.3"), ("api_auth", "false"), ("pri", "10")];
        let api = Api::from_service(&service(&txt), ApiKind::Query, "mDNS").unwrap();
        assert_eq!(api.url, "http://192.168.10.2:8080");
        assert_eq!(
            (api.versions.clone(), api.priority, api.auth),
            (vec!["v1.2".into(), "v1.3".into()], Some(10), false)
        );
        assert!(api.readable());
        let https = Api::from_service(&service(&[("api_proto", "HTTPS")]), ApiKind::Query, "mDNS").unwrap();
        assert_eq!(https.url, "https://registry-a.local:8080");
        assert_eq!(Api::from_service(&service(&[("api_proto", "ws")]), ApiKind::Query, "mDNS"), None);
        let no_address = Service { addresses: vec![], ..service(&[]) };
        assert_eq!(Api::from_service(&no_address, ApiKind::Query, "mDNS"), None, "not until its address is known");
        let node = [("ver_slf", "3"), ("ver_snd", "7"), ("api_ver", "v2.0")];
        let node = Api::from_service(&service(&node), ApiKind::Node, "mDNS").unwrap();
        assert_eq!(node.counters.len(), 2);
        assert!(!node.readable());
    }

    #[test]
    fn prefers_open_registries_in_use_by_priority() {
        let api = |url: &str, pri: Option<u32>, auth: bool| Api {
            priority: pri,
            auth,
            ..Api::given(&format!("http://{url}"))
        };
        let apis = [
            api("dev", Some(100), false),
            api("backup", Some(20), false),
            api("locked", Some(0), true),
            api("main", Some(10), false),
            api("unsaid", None, false),
        ];
        let order: Vec<&str> = by_preference(&apis).iter().map(|a| a.url.trim_start_matches("http://")).collect();
        assert_eq!(order, ["main", "backup", "unsaid", "dev", "locked"]);
    }

    #[test]
    fn unicast_registries_outrank_multicast_ones_and_ties_are_shuffled() {
        let api = |url: &str, pri: u32, by: &str| Api {
            priority: Some(pri),
            by: by.into(),
            ..Api::given(&format!("http://{url}"))
        };
        let apis =
            [api("lab", 0, MDNS), api("site-b", 10, "DNS in example.com"), api("site-a", 10, "DNS in example.com")];
        let order: Vec<&str> = by_preference(&apis).iter().map(|a| a.url.trim_start_matches("http://")).collect();
        assert_eq!(order.len(), 2, "the mDNS registry is left out: {order:?}");
        // The same order every time while the program runs.
        assert_eq!(by_preference(&apis), by_preference(&apis));
        // Without unicast ones, mDNS registries are used.
        assert_eq!(by_preference(&apis[..1]).len(), 1);
        // Ties are not settled by URL: over many names, some come out of alphabetical order.
        let many: Vec<Api> = (0..20).map(|n| api(&format!("r{n:02}"), 10, MDNS)).collect();
        let order: Vec<&str> = by_preference(&many).iter().map(|a| a.url.as_str()).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_ne!(order, sorted);
    }
}
