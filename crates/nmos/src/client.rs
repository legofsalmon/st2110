//! Reads a [`Snapshot`] from a registry's IS-04 Query API, or from one Node's Node API.
//!
//! ```no_run
//! use st2110_nmos::client::{Options, QueryClient};
//!
//! let snapshot = QueryClient::connect("http://registry.example:8080", &Options::default())?.snapshot()?;
//! let report = st2110_nmos::check(&snapshot);
//! for f in &report.findings {
//!     let at = f.resource.as_ref().map_or("registry".to_string(), |r| r.describe());
//!     println!("{at}: {} {}: {}", f.severity, f.rule, f.message);
//! }
//! # Ok::<_, st2110_nmos::client::Error>(())
//! ```

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::Value;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

use crate::check::is_http;
use crate::routing::transport_file_urls;
use crate::{Kind, Manifest, Snapshot};

/// The IS-04 versions this client reads, oldest first.
const VERSIONS: [&str; 4] = ["v1.0", "v1.1", "v1.2", "v1.3"];

/// The most a Query API response may hold. Registries that do not page return every
/// resource of a type at once.
const BODY_LIMIT: u64 = 256 << 20;

/// The most an SDP file may hold. They are a few kilobytes, and many are fetched at once.
const SDP_LIMIT: u64 = 1 << 20;

/// How a [`QueryClient`] talks to the registry.
#[derive(Clone, Debug)]
pub struct Options {
    /// How long one request may take, from connecting to the last byte.
    pub timeout: Duration,
    /// Resources to ask for per page.
    pub page_size: usize,
    /// Whether to fetch each RTP Sender's SDP file from its `manifest_href`.
    pub fetch_sdp: bool,
    /// Requests to make at once when fetching SDP files.
    pub parallel: usize,
    /// Whether to use the proxy that `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` names
    /// (except for hosts in `NO_PROXY`).
    pub env_proxy: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(5), page_size: 100, fetch_sdp: true, parallel: 16, env_proxy: true }
    }
}

/// A request that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The URL that was requested.
    pub url: String,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.url, self.message)
    }
}

impl std::error::Error for Error {}

fn error(url: &str, message: impl Into<String>) -> Error {
    Error { url: url.to_string(), message: message.into() }
}

/// A response: status, the paging headers and the body.
struct Response {
    status: u16,
    paged: bool,
    since: Option<String>,
    until: Option<String>,
    body: String,
}

/// The page of a collection to ask for next.
enum Page {
    /// No paging parameters: everything, or the registry's own first page.
    First,
    /// The next resources in creation order, after this cursor.
    After(String),
    /// The previous page in the registry's own order, which is newest first: the
    /// resources up to and including this cursor.
    UpTo(String),
}

/// What the clients share: the HTTP agent, and how they ask.
#[derive(Clone, Debug)]
struct Http {
    agent: Agent,
    options: Options,
}

impl Http {
    fn new(options: &Options) -> Self {
        let proxy = if options.env_proxy { ureq::Proxy::try_from_env() } else { None };
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(options.timeout))
            .http_status_as_error(false)
            .proxy(proxy)
            .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
            .user_agent(concat!("st2110-nmos/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, options: options.clone() }
    }

    /// Finds the API at `url`, which may name the host (`http://registry:8080`), the
    /// API's root (`…/x-nmos/query/`) or one version of it (`…/x-nmos/query/v1.3/`),
    /// which is then used as it is. Otherwise picks the newest IS-04 version the API
    /// offers, up to v1.3. Gives the versioned base URL, ending in `/`, and the version.
    fn find(&self, url: &str, api: &str, name: &str) -> Result<(String, String), Error> {
        let trimmed = url.trim().trim_end_matches('/');
        let scheme = trimmed.split_once("://").map(|(scheme, _)| scheme.to_ascii_lowercase());
        if !matches!(scheme.as_deref(), Some("http" | "https")) {
            return Err(error(url, "not an http:// or https:// URL"));
        }
        let path = format!("/x-nmos/{api}");
        if let Some((root, version)) = trimmed.rsplit_once('/')
            && root.ends_with(&path)
        {
            if !VERSIONS.contains(&version) {
                return Err(error(url, format!("{version} is not an IS-04 version this client reads (v1.0 to v1.3)")));
            }
            return Ok((format!("{trimmed}/"), version.to_string()));
        }
        let root = if trimmed.ends_with(&path) { format!("{trimmed}/") } else { format!("{trimmed}{path}/") };
        let response = self.get(&root, "application/json", BODY_LIMIT)?;
        if response.status != 200 {
            return Err(error(&root, format!("HTTP {}: no IS-04 {name} here", response.status)));
        }
        let offered: Vec<String> = serde_json::from_str(&response.body)
            .map_err(|e| error(&root, format!("expected the list of API versions: {e}")))?;
        let version = VERSIONS
            .iter()
            .rev()
            .find(|v| offered.iter().any(|o| o.trim_end_matches('/') == **v))
            .ok_or_else(|| error(&root, format!("offers {}, none of v1.0 to v1.3", offered.join(", "))))?;
        Ok((format!("{root}{version}/"), version.to_string()))
    }

    fn get(&self, url: &str, accept: &str, limit: u64) -> Result<Response, Error> {
        // Transport files change when a Sender is reconfigured, so none may come from a
        // cache (IS-05 v1.2 Behaviour: Transport Files & Caching).
        let mut response = self
            .agent
            .get(url)
            .header("Accept", accept)
            .header("Cache-Control", "no-cache")
            .call()
            .map_err(|e| error(url, e.to_string()))?;
        let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        let paged = header("X-Paging-Limit").is_some();
        let since = header("X-Paging-Since");
        let until = header("X-Paging-Until");
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_string()
            .map_err(|e| error(url, format!("reading the response: {e}")))?;
        Ok(Response { status, paged, since, until, body })
    }

    /// Reads a JSON response that must be there: HTTP 200.
    fn json<T: serde::de::DeserializeOwned>(&self, url: &str, what: &str) -> Result<T, Error> {
        let response = self.get(url, "application/json", BODY_LIMIT)?;
        if response.status != 200 {
            return Err(error(url, format!("HTTP {}", response.status)));
        }
        serde_json::from_str(&response.body).map_err(|e| error(url, format!("expected {what}: {e}")))
    }

    fn manifest(&self, href: &str) -> Manifest {
        match self.get(href, "application/sdp, text/plain;q=0.9, */*;q=0.8", SDP_LIMIT) {
            Ok(response) if (200..300).contains(&response.status) => {
                Manifest { url: href.to_string(), status: Some(response.status), sdp: Some(response.body), error: None }
            }
            Ok(response) => Manifest { url: href.to_string(), status: Some(response.status), sdp: None, error: None },
            Err(e) => Manifest { url: href.to_string(), status: None, sdp: None, error: Some(e.message) },
        }
    }

    /// Fetches transport files, several at once, in the order of `urls`.
    fn fetch(&self, urls: &[&str]) -> Vec<Manifest> {
        let next = AtomicUsize::new(0);
        let fetched = Mutex::new(Vec::with_capacity(urls.len()));
        std::thread::scope(|scope| {
            for _ in 0..self.options.parallel.clamp(1, urls.len().max(1)) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(url) = urls.get(i) else { break };
                        let manifest = self.manifest(url);
                        fetched.lock().expect("no fetch panics while holding the lock").push((i, manifest));
                    }
                });
            }
        });
        let mut fetched = fetched.into_inner().expect("no fetch panics while holding the lock");
        fetched.sort_unstable_by_key(|(i, _)| *i);
        fetched.into_iter().map(|(_, manifest)| manifest).collect()
    }

    /// Reads every resource with `list` and, unless [`Options::fetch_sdp`] is off, each
    /// RTP Sender's SDP file: from its `manifest_href`, and from its Connection API's
    /// `/transportfile` too where that is another URL.
    fn snapshot(
        &self,
        base: &str,
        version: &str,
        list: impl Fn(Kind) -> Result<Vec<Value>, Error>,
    ) -> Result<Snapshot, Error> {
        let mut snapshot = Snapshot {
            source: Some(base.to_string()),
            api_version: Some(version.to_string()),
            nodes: list(Kind::Node)?,
            devices: list(Kind::Device)?,
            sources: list(Kind::Source)?,
            flows: list(Kind::Flow)?,
            senders: list(Kind::Sender)?,
            receivers: list(Kind::Receiver)?,
            ..Snapshot::default()
        };
        if self.options.fetch_sdp {
            let manifests = manifest_urls(&snapshot.senders);
            let transport_files = transport_file_urls(&snapshot);
            let urls: Vec<&str> = manifests.iter().chain(&transport_files).map(|(_, url)| url.as_str()).collect();
            let mut fetched = self.fetch(&urls).into_iter();
            let split = manifests.len();
            snapshot.manifests = manifests.into_iter().map(|(id, _)| id).zip(fetched.by_ref().take(split)).collect();
            snapshot.transport_files = transport_files.into_iter().map(|(id, _)| id).zip(fetched).collect();
        }
        Ok(snapshot)
    }
}

/// Each RTP Sender with an HTTP(S) `manifest_href`, and that URL.
fn manifest_urls(senders: &[Value]) -> Vec<(String, String)> {
    senders
        .iter()
        .filter(|s| {
            s.get("transport").and_then(Value::as_str).is_some_and(|t| t.starts_with("urn:x-nmos:transport:rtp"))
        })
        .filter_map(|s| {
            let id = s.get("id")?.as_str()?;
            let href = s.get("manifest_href")?.as_str()?;
            is_http(href).then(|| (id.to_string(), href.to_string()))
        })
        .collect()
}

/// A client for one registry's Query API.
#[derive(Clone, Debug)]
pub struct QueryClient {
    http: Http,
    base: String,
    version: String,
}

impl QueryClient {
    /// Connects to a Query API and picks the newest IS-04 version it offers, up to v1.3.
    ///
    /// `url` may name the host (`http://registry:8080`), the API's root
    /// (`…/x-nmos/query/`) or one version of it (`…/x-nmos/query/v1.3/`), which is then
    /// used as it is.
    pub fn connect(url: &str, options: &Options) -> Result<Self, Error> {
        let http = Http::new(options);
        let (base, version) = http.find(url, "query", "Query API")?;
        Ok(Self { http, base, version })
    }

    /// The Query API version in use, such as `v1.3`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The versioned base URL, ending in `/`.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Lists every resource of one type, paging through the collection in creation
    /// order. Resources registered at older IS-04 versions are included where the
    /// registry supports downgrade queries.
    pub fn list(&self, kind: Kind) -> Result<Vec<Value>, Error> {
        let collection = format!("{}{}/", self.base, kind.plural());
        // A registry answers 501 to paging or downgrade queries it does not implement,
        // without saying which, so try each combination in turn: paging, downgrade.
        // IS-04 v1.0 has neither, and its registries may read unknown parameters as
        // filters that match nothing.
        let v1_0 = self.version == "v1.0";
        let mut attempts = [(true, true), (false, true), (true, false), (false, false)]
            .into_iter()
            .filter(|&attempt| !v1_0 || attempt == (false, false));
        let (mut paging, mut downgrade) = attempts.next().expect("at least one attempt");
        let first = |paging: bool| if paging { Page::After("0:0".into()) } else { Page::First };
        let mut page = first(paging);
        let mut resources = Vec::new();
        let mut seen = HashSet::new();
        // A bound on pages, in case a registry's cursors never reach the end.
        for _ in 0..100_000 {
            let mut query = Vec::new();
            match &page {
                Page::First => {}
                Page::After(since) => query.push(format!(
                    "paging.order=create&paging.since={since}&paging.limit={}",
                    self.http.options.page_size
                )),
                Page::UpTo(until) => query.push(format!("paging.until={until}")),
            }
            if downgrade {
                query.push("query.downgrade=v1.0".to_string());
            }
            let url = if query.is_empty() { collection.clone() } else { format!("{collection}?{}", query.join("&")) };
            let response = self.http.get(&url, "application/json", BODY_LIMIT)?;
            if response.status == 501
                && resources.is_empty()
                && let Some(next) = attempts.next()
            {
                (paging, downgrade) = next;
                page = first(paging);
                continue;
            }
            if response.status != 200 {
                return Err(error(&url, format!("HTTP {}", response.status)));
            }
            let items: Vec<Value> = serde_json::from_str(&response.body)
                .map_err(|e| error(&url, format!("expected a JSON array of {}: {e}", kind.plural())))?;
            let empty = items.is_empty();
            let before = resources.len();
            for resource in items {
                let id = resource.get("id").and_then(Value::as_str).map(str::to_string);
                if id.is_none_or(|id| seen.insert(id)) {
                    resources.push(resource);
                }
            }
            // Without X-Paging-Limit the registry is not paging: that was everything.
            if !response.paged || empty {
                return Ok(resources);
            }
            if resources.len() == before {
                return Err(error(&url, "the registry's paging cursors do not advance: a page held nothing new"));
            }
            // A registry may page a query that asked for no paging, newest first, as
            // IS-04 allows: then read on backwards from the start of that page.
            page = match (page, response.since, response.until) {
                (Page::After(since), _, Some(until)) if until != since => Page::After(until),
                (Page::First, Some(since), _) => Page::UpTo(since),
                (Page::UpTo(until), Some(since), _) if since != until => Page::UpTo(since),
                _ => return Ok(resources),
            };
        }
        Err(error(&collection, "the registry's paging cursors never reached the end of the collection"))
    }

    /// Reads one resource by its `id`, or `None` when the registry does not hold it.
    /// A resource registered at an older IS-04 version is read too, where the registry
    /// supports downgrade queries; without one, IS-04 answers 409 for it.
    pub fn resource(&self, kind: Kind, id: &str) -> Result<Option<Value>, Error> {
        let plain = format!("{}{}/{id}", self.base, kind.plural());
        let mut url = plain.clone();
        if self.version != "v1.0" {
            url.push_str("?query.downgrade=v1.0");
        }
        let mut response = self.http.get(&url, "application/json", BODY_LIMIT)?;
        // A registry without downgrade queries answers 501, or 400.
        if url != plain && matches!(response.status, 400 | 501) {
            url = plain;
            response = self.http.get(&url, "application/json", BODY_LIMIT)?;
        }
        match response.status {
            200 => serde_json::from_str(&response.body)
                .map(Some)
                .map_err(|e| error(&url, format!("expected a JSON {}: {e}", kind.as_str()))),
            404 => Ok(None),
            status => Err(error(&url, format!("HTTP {status}"))),
        }
    }

    /// Fetches a transport file. Failures are recorded in the result, not returned.
    pub fn manifest(&self, href: &str) -> Manifest {
        self.http.manifest(href)
    }

    /// Fetches transport files, several at once, in the order of `hrefs`.
    pub fn manifests(&self, hrefs: &[&str]) -> Vec<Manifest> {
        self.http.fetch(hrefs)
    }

    /// Reads every resource and, unless [`Options::fetch_sdp`] is off, each RTP
    /// Sender's SDP file: from its `manifest_href`, and from its Connection API's
    /// `/transportfile` too where that is another URL.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.http.snapshot(&self.base, &self.version, |kind| self.list(kind))
    }
}

/// A client for one Node's Node API, which a controller reads peer to peer where it
/// finds no registry.
///
/// ```no_run
/// use st2110_nmos::client::{NodeClient, Options};
///
/// let node = NodeClient::connect("http://192.168.10.21", &Options::default())?;
/// let snapshot = node.snapshot()?;
/// println!("{} senders on {}", snapshot.senders.len(), node.base());
/// # Ok::<_, st2110_nmos::client::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct NodeClient {
    http: Http,
    base: String,
    version: String,
}

impl NodeClient {
    /// Connects to a Node API and picks the newest IS-04 version it offers, up to v1.3.
    ///
    /// `url` may name the host (`http://192.168.10.21`), the API's root
    /// (`…/x-nmos/node/`) or one version of it (`…/x-nmos/node/v1.3/`), which is then
    /// used as it is.
    pub fn connect(url: &str, options: &Options) -> Result<Self, Error> {
        let http = Http::new(options);
        let (base, version) = http.find(url, "node", "Node API")?;
        Ok(Self { http, base, version })
    }

    /// The Node API version in use, such as `v1.3`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The versioned base URL, ending in `/`.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Lists the Node's resources of one type: for [`Kind::Node`], the Node itself.
    pub fn list(&self, kind: Kind) -> Result<Vec<Value>, Error> {
        if kind == Kind::Node {
            let url = format!("{}self/", self.base);
            return self.http.json(&url, "the Node's own resource").map(|node: Value| vec![node]);
        }
        let url = format!("{}{}/", self.base, kind.plural());
        self.http.json(&url, &format!("a JSON array of {}", kind.plural()))
    }

    /// Fetches a transport file. Failures are recorded in the result, not returned.
    pub fn manifest(&self, href: &str) -> Manifest {
        self.http.manifest(href)
    }

    /// Fetches transport files, several at once, in the order of `hrefs`.
    pub fn manifests(&self, hrefs: &[&str]) -> Vec<Manifest> {
        self.http.fetch(hrefs)
    }

    /// Reads the Node, its resources and, unless [`Options::fetch_sdp`] is off, each
    /// RTP Sender's SDP file, as [`QueryClient::snapshot`] reads a registry.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.http.snapshot(&self.base, &self.version, |kind| self.list(kind))
    }
}
