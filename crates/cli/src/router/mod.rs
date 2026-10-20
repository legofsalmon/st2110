//! `st2110 router`: a router panel in the browser. The page shows which Senders each
//! Receiver can take as a crosspoint grid, and a click connects them through IS-05.
//!
//! This command serves the page, and does the work it asks for: it reads the registry
//! and makes connections with `st2110 connect`'s controller, salvos and rollbacks
//! included. The browser talks only to it, so devices need not allow a page from
//! another site to send them requests, and no video passes through the browser.
//!
//! The page also turns a Sender on and off and changes where it sends, through the
//! same controller ([`controller::control`]).
//!
//! The page hears of each change over a WebSocket ([`events`]), as the router hears of
//! them from the registry's subscriptions. Requests to the registry and the Nodes carry
//! an IS-10 token where they ask for one. The log of connections made, and the demo
//! facility's connections, are kept in a file between runs ([`keep`]).
//!
//! Anyone who can reach the page can make connections. It listens on this machine's
//! loopback address unless told otherwise, and answers only requests addressed to an
//! IP address or `localhost`, and connection requests and WebSockets from the page
//! itself, so another web site cannot make them through a visitor's browser.

mod demo;
mod events;
mod http;
mod keep;
mod preview;
mod signal;

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};
use st2110_connect::client::{self, ConnectionClient};
use st2110_connect::controller::{self, Route, SenderControl, Settings, Take};
use st2110_connect::{Destination, SenderChange};
use st2110_nmos::auth::{ClientCredentials, Token};
use st2110_nmos::client::{Options, QueryClient};
use st2110_nmos::{Kind, Manifest, Snapshot, routing};

use self::demo::Facility;
use self::events::{Hub, Sent, Signal, Subscriptions};
use self::http::{Request, Response};
use self::keep::Keeper;
use self::preview::Previews;
use crate::seconds;

pub(crate) use self::keep::default_path as default_state;

/// The page.
const PAGE: &str = include_str!("page.html");

/// The most connections one request may make.
const MOST: usize = 512;

/// The fewest streams previewed at once with `--demo`: every one of its Senders.
const DEMO_PREVIEWS: usize = 16;

/// The command's arguments, as given.
pub(crate) struct Args {
    pub target: Option<String>,
    pub demo: bool,
    pub listen: String,
    pub open: bool,
    pub timeout: f64,
    pub lead: f64,
    pub wait: f64,
    pub tai_utc: i32,
    pub previews: usize,
    pub interface: Option<Ipv4Addr>,
    pub auth: crate::auth::Auth,
    pub demo_auth: bool,
    /// The state file, or `None` to keep nothing.
    pub state: Option<PathBuf>,
}

/// A Sender's SDP file, and the Sender's `version` and `manifest_href` when it was fetched.
struct Fetched {
    version: Option<String>,
    href: String,
    manifest: Manifest,
}

/// What the server knows.
struct Router {
    /// The Query API URL.
    registry: String,
    demo: Option<Mutex<Facility>>,
    timeout: Duration,
    settings: Settings,
    /// The registry as last read, to explain crosspoints from.
    last: Mutex<Option<Snapshot>>,
    /// Each Sender's SDP file as last fetched, keyed by Sender `id`, with the Sender's
    /// `version` and `manifest_href` then: fetched again only when either changes.
    sdp: Mutex<HashMap<String, Fetched>>,
    /// Held while connections are made, so that two salvos do not cross.
    taking: Mutex<()>,
    /// The streams received for the page's previews.
    previews: Arc<Previews>,
    /// The IS-10 token sent to the registry and the Nodes, if they ask for one.
    token: Option<Token>,
    /// The pages connected to `/api/events`.
    pages: Hub,
    /// Raised when the registry may have changed, to read it again.
    changes: Signal,
    /// What the pages were last sent of the registry.
    sent: Mutex<Sent>,
    /// The registry's subscriptions, and which are connected.
    subscriptions: Subscriptions,
    /// The connections made from the page, oldest first, as kept.
    log: Mutex<Vec<Value>>,
    /// Numbers the log's entries.
    entries: AtomicU64,
    /// Where the log and the demo facility are kept between runs.
    keeper: Keeper,
    /// The demo registry's subscriptions' WebSockets, each with its subscription's id.
    demo_sockets: Hub,
}

pub(crate) fn run(args: &Args) -> io::Result<ExitCode> {
    match serve(args) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(Failure::Usage(message)) => {
            eprintln!("st2110: {message}");
            Ok(ExitCode::from(2))
        }
        Err(Failure::Io(e)) => Err(e),
    }
}

enum Failure {
    Usage(String),
    Io(io::Error),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Usage(message)
    }
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn serve(args: &Args) -> Result<(), Failure> {
    let timeout = seconds("--timeout", args.timeout)?;
    if timeout.is_zero() {
        return Err(Failure::Usage("--timeout 0 is not a number of seconds above 0".into()));
    }
    let settings = Settings {
        lead: seconds("--lead", args.lead)?,
        wait: seconds("--wait", args.wait)?,
        tai_utc: args.tai_utc,
        ..Settings::default()
    };
    let listener =
        TcpListener::bind(&args.listen).map_err(|e| Failure::Usage(format!("--listen {}: {e}", args.listen)))?;
    let address = listener.local_addr()?;
    // Where this machine reaches the server: the loopback address when it listens on all.
    let local = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => format!("127.0.0.1:{}", address.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => format!("[::1]:{}", address.port()),
        _ => address.to_string(),
    };
    let page = format!("http://{local}/");
    let (registry, demo) = match (&args.target, args.demo) {
        (Some(target), false) => {
            let lower = target.to_ascii_lowercase();
            if !lower.starts_with("http://") && !lower.starts_with("https://") {
                return Err(Failure::Usage(format!("{target} is not a registry's http:// or https:// URL")));
            }
            (target.clone(), None)
        }
        (None, true) => {
            let base = format!("http://{local}");
            let facility = Facility::new(&base, args.tai_utc);
            let facility = if args.demo_auth { facility.with_auth() } else { facility };
            (format!("{base}/x-nmos/query/v1.3/"), Some(facility))
        }
        _ => return Err(Failure::Usage("give a registry's Query API URL, or --demo".into())),
    };
    let token = match demo.as_ref().and_then(Facility::auth_server) {
        Some(server) => Some(Token::client_credentials(
            ClientCredentials {
                server,
                client_id: demo::CLIENT_ID.into(),
                client_secret: demo::CLIENT_SECRET.into(),
                scope: st2110_nmos::auth::SCOPES.into(),
            },
            timeout,
            false,
        )),
        None => args.auth.token(timeout, demo.is_none())?,
    };
    let keeper = Keeper::new(args.state.clone(), if demo.is_some() { "demo" } else { registry.as_str() });
    let kept = keeper.load();
    let demo = demo.map(|mut facility| {
        if let Some(saved) = &kept.demo {
            facility.restore(saved);
        }
        Mutex::new(facility)
    });
    let entries = kept.log.len() as u64;
    let router = Arc::new(Router {
        registry,
        demo,
        timeout,
        settings,
        last: Mutex::new(None),
        sdp: Mutex::default(),
        taking: Mutex::new(()),
        token,
        pages: Hub::default(),
        changes: Signal::default(),
        sent: Mutex::default(),
        subscriptions: Subscriptions::default(),
        log: Mutex::new(kept.log),
        entries: AtomicU64::new(entries),
        keeper,
        demo_sockets: Hub::default(),
        // The demo's streams come over the loopback interface.
        previews: Previews::new(
            if args.demo { Some(Ipv4Addr::LOCALHOST) } else { args.interface },
            args.tai_utc,
            // The demo's streams are small, and all of them fit.
            if args.demo && args.previews > 0 { args.previews.max(DEMO_PREVIEWS) } else { args.previews },
        ),
    });
    // Without previews nothing would show the demo's streams, so they are not sent.
    if let Some(demo) = router.demo.as_ref().filter(|_| args.previews > 0) {
        let streams = demo.lock().map(|f| f.streams()).unwrap_or_default();
        if let Err(e) = signal::start(&streams, args.tai_utc) {
            eprintln!("st2110: the demo's streams cannot be sent, so there are no previews: {e}");
        }
    }
    {
        let mut out = io::stdout().lock();
        writeln!(out, "Router: {page}")?;
        match &router.demo {
            Some(_) => writeln!(out, "Registry: the demo facility, at {}", router.registry)?,
            None => writeln!(out, "Registry: {}", router.registry)?,
        }
        if let Some(server) = router.demo.as_ref().and_then(|d| d.lock().ok()?.auth_server()) {
            writeln!(
                out,
                "IS-10: the demo asks for tokens, from {server} (client {}, secret {})",
                demo::CLIENT_ID,
                demo::CLIENT_SECRET
            )?;
        } else if let Some(token) = &router.token {
            writeln!(out, "IS-10: {}", token.describe())?;
        }
        match router.keeper.path() {
            Some(path) => writeln!(out, "Kept in: {}", path.display())?,
            None => writeln!(out, "Kept in: nothing (--no-state)")?,
        }
        if !address.ip().is_loopback() {
            writeln!(out, "Anyone who can reach {address} can make connections. Ctrl-C stops the router.")?;
        } else {
            writeln!(out, "Ctrl-C stops the router.")?;
        }
        out.flush()?;
    }
    if args.open {
        open(&page);
    }
    events::start(&router);
    if router.demo.is_some() {
        let r = router.clone();
        std::thread::spawn(move || run_demo(&r));
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let router = router.clone();
        std::thread::spawn(move || handle(&router, &stream));
    }
    Ok(())
}

/// Opens the page in the default browser, when this machine has a way to.
fn open(page: &str) {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(e) = std::process::Command::new(program).arg(page).spawn() {
        eprintln!("st2110: could not open a browser ({program}: {e}); open {page}");
    }
}

fn handle(router: &Arc<Router>, stream: &TcpStream) {
    let Ok(Some(request)) = http::read(stream) else {
        return;
    };
    if events::is_upgrade(&request) {
        return upgrade(router, stream, &request);
    }
    let response = answer(router, &request);
    let _ = http::write(stream, &response);
    if let Some(demo) = &router.demo
        && Facility::serves(&request.path)
    {
        push_demo_changes(router, demo);
    }
}

/// A request to become a WebSocket: the page's `/api/events`, or a subscription to the
/// demo registry.
fn upgrade(router: &Arc<Router>, stream: &TcpStream, request: &Request) {
    let refuse = |status, message: &str| {
        let _ = http::write(stream, &Response::error(status, message));
    };
    if !host_allowed(request.header("Host")) {
        return refuse(403, "address the router by its IP address or localhost");
    }
    match request.path.as_str() {
        "/api/events" => {
            // A browser sends Origin with every WebSocket, and a page from another site
            // may open one here: only this server's own page may.
            let host = request.header("Host").unwrap_or_default();
            if request.header("Origin").is_some_and(|o| !o.eq_ignore_ascii_case(&format!("http://{host}"))) {
                return refuse(403, "only the router's own page may listen here");
            }
            events::page(router, stream, request);
        }
        demo::WS_PATH if router.demo.is_some() => {
            let Some(demo) = &router.demo else { return };
            let uid = request.param("uid").unwrap_or_default();
            let sync = {
                let Ok(mut facility) = demo.lock() else { return };
                if let Err(refused) = facility.authorized(request) {
                    let _ = http::write(stream, &refused);
                    return;
                }
                if facility.subscription(&uid).is_none() {
                    return refuse(404, "no such subscription");
                }
                facility.sync(&uid)
            };
            if let Err((status, message)) = events::accept(stream, request) {
                return refuse(status, &message);
            }
            let Some(client) = router.demo_sockets.add(&uid, stream, 64) else { return };
            if let Some(sync) = sync {
                let _ = client.send(&st2110_nmos::ws::Frame::Text(sync));
            }
            router.demo_sockets.hold(&client, stream);
        }
        _ => refuse(404, "nothing here"),
    }
}

/// Keeps the demo facility going: its scheduled activations happen when they are due,
/// whether or not anything asks.
fn run_demo(router: &Router) {
    let Some(demo) = &router.demo else { return };
    loop {
        std::thread::sleep(Duration::from_millis(20));
        if let Ok(mut facility) = demo.lock() {
            facility.settle();
        }
        push_demo_changes(router, demo);
    }
}

/// Pushes the demo registry's changes to its subscriptions, and keeps its Receivers.
fn push_demo_changes(router: &Router, demo: &Mutex<Facility>) {
    let (messages, kept) = {
        let Ok(mut facility) = demo.lock() else { return };
        let messages = facility.take_changes();
        let kept = facility.take_dirty().then(|| facility.export());
        (messages, kept)
    };
    for (uid, message) in messages {
        router.demo_sockets.send(|topic| topic == uid, &message);
    }
    if let Some(kept) = kept {
        router.keeper.update(|section| section.demo = Some(kept));
    }
}

/// Whether a `Host` header names this server by an IP address or `localhost`. A page
/// from another site that has pointed its own name at this machine, to read from it or
/// send it requests as if from that site, sends its name instead.
fn host_allowed(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let (name, port) = match host.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((ip, after)) => (ip, after.strip_prefix(':').or(if after.is_empty() { None } else { Some("") })),
            None => return false,
        },
        None => match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        },
    };
    // The page echoes the host into what it may connect to, so nothing but a port follows.
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok && (name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().is_ok())
}

/// Whether a request that changes something came from the page itself: JSON, which a
/// page from another site cannot send here without asking first, and when the browser
/// says where it came from, from this server.
fn same_origin(request: &Request) -> Result<(), String> {
    let json = request
        .header("Content-Type")
        .and_then(|t| t.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err("send the request as application/json".into());
    }
    if let Some(origin) = request.header("Origin") {
        let host = request.header("Host").unwrap_or_default();
        if !origin.eq_ignore_ascii_case(&format!("http://{host}")) {
            return Err(format!("requests from {origin} are not taken"));
        }
    }
    if request.header("Sec-Fetch-Site").is_some_and(|site| !matches!(site, "same-origin" | "none")) {
        return Err("requests from other sites are not taken".into());
    }
    Ok(())
}

fn answer(router: &Router, request: &Request) -> Response {
    if !host_allowed(request.header("Host")) {
        return Response::error(403, "address the router by its IP address or localhost");
    }
    if let Some(demo) = &router.demo
        && Facility::serves(&request.path)
    {
        return demo
            .lock()
            .map_or_else(|_| Response::error(500, "the demo facility failed"), |mut f| f.answer(request));
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            headers: vec![
                (
                    "Content-Security-Policy",
                    // `'self'` covers the page's own WebSocket in some browsers only.
                    format!(
                        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                         connect-src 'self' ws://{}; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; \
                         form-action 'none'",
                        request.header("Host").unwrap_or_default()
                    ),
                ),
                ("X-Frame-Options", "DENY".into()),
                ("Referrer-Policy", "no-referrer".into()),
            ],
            body: PAGE.as_bytes().to_vec(),
        },
        ("GET", "/api/state") => state(router),
        ("GET", "/api/why") => why(router, request),
        ("POST", "/api/take") => match same_origin(request) {
            Ok(()) => take(router, request),
            Err(message) => Response::error(403, message),
        },
        ("POST", "/api/sender") => match same_origin(request) {
            Ok(()) => sender(router, request),
            Err(message) => Response::error(403, message),
        },
        ("POST", "/api/watch") => match same_origin(request) {
            Ok(()) => watch(router, request),
            Err(message) => Response::error(403, message),
        },
        ("GET", "/api/live") => live(router),
        ("GET", "/api/log") => {
            let log = router.log.lock().map(|l| l.clone()).unwrap_or_default();
            Response::json(200, &json!({"log": log}))
        }
        ("GET", "/api/preview") => picture(router, request),
        ("GET", "/api/stream") => stream(router, request),
        (
            _,
            "/" | "/api/state" | "/api/why" | "/api/take" | "/api/sender" | "/api/watch" | "/api/live" | "/api/log"
            | "/api/preview" | "/api/stream" | "/api/events",
        ) => Response::error(405, "not with that method"),
        _ => Response::error(404, "nothing here"),
    }
}

impl Router {
    fn query_client(&self, fetch_sdp: bool) -> Result<QueryClient, String> {
        let options = Options {
            timeout: self.timeout,
            fetch_sdp,
            env_proxy: self.demo.is_none(),
            token: self.token.clone(),
            ..Options::default()
        };
        QueryClient::connect(&self.registry, &options).map_err(|e| e.to_string())
    }

    /// Adds each RTP Sender's SDP file to `snapshot`, for the capability checks that
    /// are judged on it. The page reads the registry every few seconds, so a file is
    /// fetched again only when its Sender's `version` or `manifest_href` changes, as
    /// they do when the Sender is reconfigured.
    fn add_sdp(&self, registry: &QueryClient, snapshot: &mut Snapshot) {
        let wanted: Vec<(String, Option<String>, String)> = snapshot
            .senders
            .iter()
            .filter(|s| text(s, "transport").is_some_and(|t| t.starts_with("urn:x-nmos:transport:rtp")))
            .filter_map(|s| {
                let href =
                    text(s, "manifest_href").filter(|h| h.starts_with("http://") || h.starts_with("https://"))?;
                Some((text(s, "id")?, text(s, "version"), href))
            })
            .collect();
        let Ok(mut cache) = self.sdp.lock() else {
            return;
        };
        cache.retain(|id, _| wanted.iter().any(|(w, ..)| w == id));
        let stale: Vec<&(String, Option<String>, String)> = wanted
            .iter()
            .filter(|(id, version, href)| {
                cache.get(id).is_none_or(|f| f.version != *version || f.href != *href || f.manifest.sdp.is_none())
            })
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let fetched = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..stale.len().min(16) {
                scope.spawn(|| {
                    while let Some((id, version, href)) =
                        stale.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    {
                        let manifest = registry.manifest(href);
                        if let Ok(mut fetched) = fetched.lock() {
                            fetched
                                .push((id.clone(), Fetched { version: version.clone(), href: href.clone(), manifest }));
                        }
                    }
                });
            }
        });
        cache.extend(fetched.into_inner().unwrap_or_default());
        snapshot.manifests = cache.iter().map(|(id, f)| (id.clone(), f.manifest.clone())).collect();
    }

    fn connection_client(&self) -> ConnectionClient {
        ConnectionClient::new(&client::Options {
            timeout: self.timeout,
            env_proxy: self.demo.is_none(),
            token: self.token.clone(),
        })
    }

    /// Whether every subscription to the registry is connected, so that the router hears
    /// of each change as it happens.
    fn subscribed(&self) -> bool {
        self.subscriptions.all()
    }

    fn note_subscription(&self, path: &str, problem: Option<String>) {
        self.subscriptions.note(path, problem);
    }

    /// Where the IS-10 token comes from, for the page.
    fn auth_note(&self) -> Option<String> {
        self.token.as_ref().map(Token::describe)
    }

    /// Adds a take to the log, keeps it, and tells every page.
    fn record(&self, mut entry: Value) -> String {
        let n = self.entries.fetch_add(1, Ordering::Relaxed) + 1;
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis()) as u64;
        let id = format!("{at}-{n}");
        entry["id"] = json!(id);
        entry["at"] = json!(at);
        if let Ok(mut log) = self.log.lock() {
            log.push(entry.clone());
            let extra = log.len().saturating_sub(keep::LOG_LIMIT);
            log.drain(..extra);
        }
        self.keeper.update(|section| section.log.push(entry.clone()));
        self.pages.send(|_| true, &json!({"type": "log", "entry": entry}).to_string());
        id
    }
}

/// The short name of a format URN: `video`, `audio`, `data` or `mux`.
fn format_name(urn: Option<&str>) -> Option<String> {
    urn.map(|u| u.rsplit(':').next().unwrap_or(u).to_string())
}

fn text(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

/// The labels of a resource's Device and Node.
fn device_and_node(snapshot: &Snapshot, resource: &Value) -> (Option<String>, Option<String>) {
    let by_id = |list: &[Value], id: Option<&str>| -> Option<Value> {
        let id = id?;
        list.iter().find(|r| r.get("id").and_then(Value::as_str) == Some(id)).cloned()
    };
    let device = by_id(&snapshot.devices, resource.get("device_id").and_then(Value::as_str));
    let node = device.as_ref().and_then(|d| by_id(&snapshot.nodes, d.get("node_id").and_then(Value::as_str)));
    (device.and_then(|d| text(&d, "label")), node.and_then(|n| text(&n, "label")))
}

/// The registry, as the page shows it.
fn state(router: &Router) -> Response {
    match state_json(router) {
        Ok(body) => Response::json(200, &body),
        Err(message) => Response::error(502, message),
    }
}

/// The registry, as the page shows it: every Sender, and every Receiver with the
/// Senders it can take and the one it takes now.
fn state_json(router: &Router) -> Result<Value, String> {
    let read = router.query_client(false).and_then(|registry| {
        let mut snapshot = registry.snapshot().map_err(|e| e.to_string())?;
        router.add_sdp(&registry, &mut snapshot);
        Ok(snapshot)
    });
    let snapshot = read.map_err(|message| format!("reading the registry: {message}"))?;
    let matrix = routing::matrix(&snapshot);
    let flows = &snapshot.flows;
    let senders: Vec<Value> = matrix
        .senders
        .iter()
        .map(|s| {
            let raw = &snapshot.senders[s.index];
            let flow = raw
                .get("flow_id")
                .and_then(Value::as_str)
                .and_then(|id| flows.iter().find(|f| f.get("id").and_then(Value::as_str) == Some(id)));
            let (device, node) = device_and_node(&snapshot, raw);
            // IS-04 v1.2 and later: whether the Sender's master_enable is on.
            let enabled = raw.get("subscription").and_then(|s| s.get("active")).and_then(Value::as_bool);
            json!({
                "id": s.id, "label": s.label, "device": device, "node": node, "enabled": enabled,
                "format": format_name(flow.and_then(|f| f.get("format")).and_then(Value::as_str)),
                "summary": text(raw, "id").and_then(|id| summary(&snapshot, &id)),
            })
        })
        .collect();
    let receivers: Vec<Value> = matrix
        .receivers
        .iter()
        .map(|row| {
            let raw = &snapshot.receivers[row.receiver.index];
            let subscription = raw.get("subscription");
            let (device, node) = device_and_node(&snapshot, raw);
            json!({
                "id": row.receiver.id, "label": row.receiver.label, "device": device, "node": node,
                "format": format_name(raw.get("format").and_then(Value::as_str)),
                "fits": row.fits, "current": row.current,
                "sender_id": subscription.and_then(|s| s.get("sender_id")).and_then(Value::as_str),
                "active": subscription.and_then(|s| s.get("active")).and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect();
    let read_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let body = json!({
        "registry": router.registry, "demo": router.demo.is_some(), "read_at": read_at as u64,
        "lead": router.settings.lead.as_secs_f64(), "previews": router.previews.most(),
        "auth": router.auth_note(), "subscribed": router.subscribed(),
        "senders": senders, "receivers": receivers,
    });
    if let Ok(mut last) = router.last.lock() {
        *last = Some(snapshot);
    }
    Ok(body)
}

/// What a Sender's SDP file declares, in a few words: its first stream's format, and
/// whether a second leg carries a copy.
fn summary(snapshot: &Snapshot, id: &str) -> Option<String> {
    let sdp = snapshot.manifests.get(id)?.sdp.as_deref()?;
    let report = st2110_sdp::lint(sdp);
    let first = report.streams.first()?.summary.clone();
    Some(match report.streams.len() {
        1 => first,
        2 => format!("{first}, ST 2022-7 pair"),
        n => format!("{first}, {n} streams"),
    })
}

/// Why a Receiver cannot take a Sender's stream, judged on the registry as last read.
fn why(router: &Router, request: &Request) -> Response {
    let (Some(sender), Some(receiver)) = (request.param("sender"), request.param("receiver")) else {
        return Response::error(400, "name a sender and a receiver");
    };
    let Ok(last) = router.last.lock() else {
        return Response::error(500, "the router failed");
    };
    let Some(snapshot) = last.as_ref() else {
        return Response::error(409, "the registry has not been read yet");
    };
    match routing::route(snapshot, &sender, &receiver, None) {
        Ok(()) => Response::json(200, &json!({"fits": true, "reason": null})),
        Err(reason) => Response::json(200, &json!({"fits": false, "reason": reason})),
    }
}

/// A connection the page asks for: a Receiver, and the Sender it is to take or `null`
/// to disconnect it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wanted {
    receiver: String,
    sender: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TakeRequest {
    routes: Vec<Wanted>,
    #[serde(default)]
    dry_run: bool,
}

/// Makes the connections the page asks for, together, as `st2110 connect --salvo` does,
/// and logs what happened for every page, and the next run, to see.
fn take(router: &Router, request: &Request) -> Response {
    let mut response = make(router, request);
    if response.status == 409 {
        // Refused for another take in progress: nothing to log.
        return response;
    }
    let mut body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    let asked: Option<TakeRequest> = serde_json::from_slice(&request.body).ok();
    let entry = match body.get("error").and_then(Value::as_str) {
        Some(error) => json!({
            "dry_run": asked.as_ref().is_some_and(|a| a.dry_run), "succeeded": false,
            "error": error, "connections": [],
        }),
        None => json!({
            "dry_run": body["dry_run"], "succeeded": body["succeeded"],
            "connections": body["connections"].as_array().into_iter().flatten().map(|c| json!({
                "state": c["state"], "describe": c["describe"],
                "problems": c["problems"], "warnings": c["warnings"], "notes": c["notes"],
            })).collect::<Vec<_>>(),
        }),
    };
    if asked.is_some() {
        body["log_id"] = json!(router.record(entry));
        response.body = body.to_string().into_bytes();
    }
    router.changes.raise();
    response
}

fn make(router: &Router, request: &Request) -> Response {
    let wanted: TakeRequest = match serde_json::from_slice(&request.body) {
        Ok(wanted) => wanted,
        Err(e) => return Response::error(400, format!("not a list of routes: {e}")),
    };
    if wanted.routes.is_empty() {
        return Response::error(400, "no connection was asked for");
    }
    if wanted.routes.len() > MOST {
        return Response::error(400, format!("at most {MOST} connections are made at once"));
    }
    let Ok(_taking) = router.taking.try_lock() else {
        return Response::error(409, "other connections are being made; try again when they are done");
    };
    let routes: Vec<Route> = wanted
        .routes
        .into_iter()
        .map(|w| Route { receiver: w.receiver, take: w.sender.map_or(Take::Nothing, Take::Sender) })
        .collect();
    // Only the resources: the controller fetches each SDP file afresh.
    let registry = match router.query_client(false) {
        Ok(registry) => registry,
        Err(message) => return Response::error(502, format!("reading the registry: {message}")),
    };
    let snapshot = match registry.snapshot() {
        Ok(snapshot) => snapshot,
        Err(e) => return Response::error(502, format!("reading the registry: {e}")),
    };
    let settings = Settings { dry_run: wanted.dry_run, ..router.settings.clone() };
    match controller::connect(&snapshot, &routes, &router.connection_client(), Some(&registry), &settings) {
        Ok(outcome) => {
            let mut body = serde_json::to_value(&outcome).unwrap_or(Value::Null);
            body["succeeded"] = json!(outcome.succeeded());
            for (value, connection) in
                body["connections"].as_array_mut().into_iter().flatten().zip(&outcome.connections)
            {
                value["describe"] = json!(format!(
                    "{} ← {}: {}",
                    connection.receiver.describe(),
                    connection.describe_take(),
                    connection.state.describe()
                ));
            }
            Response::json(200, &body)
        }
        Err(message) => Response::error(400, message),
    }
}

/// A change to a Sender the page asks for: on or off, and where each leg goes, path 1
/// first, or nothing to leave where it sends as it is.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderRequest {
    sender: String,
    enable: bool,
    #[serde(default)]
    destinations: Vec<String>,
    #[serde(default)]
    dry_run: bool,
}

/// Turns a Sender on or off, or changes where it sends, as `st2110 connect --sender`
/// does, and logs what happened as a take is logged.
fn sender(router: &Router, request: &Request) -> Response {
    let wanted: SenderRequest = match serde_json::from_slice(&request.body) {
        Ok(wanted) => wanted,
        Err(e) => return Response::error(400, format!("not a change to a sender: {e}")),
    };
    let mut destinations = Vec::new();
    for (i, text) in wanted.destinations.iter().enumerate() {
        match Destination::parse(text) {
            Ok(destination) => destinations.push(destination),
            Err(message) => return Response::error(400, format!("leg {}: {message}", i + 1)),
        }
    }
    let Ok(_taking) = router.taking.try_lock() else {
        return Response::error(409, "other connections are being made; try again when they are done");
    };
    let registry = match router.query_client(false) {
        Ok(registry) => registry,
        Err(message) => return Response::error(502, format!("reading the registry: {message}")),
    };
    let snapshot = match registry.snapshot() {
        Ok(snapshot) => snapshot,
        Err(e) => return Response::error(502, format!("reading the registry: {e}")),
    };
    let change = SenderChange { enable: wanted.enable, destinations, receiver_id: None };
    let settings = Settings { dry_run: wanted.dry_run, ..router.settings.clone() };
    let report = match controller::control(
        &snapshot,
        &wanted.sender,
        &change,
        &router.connection_client(),
        Some(&registry),
        &settings,
    ) {
        Ok(report) => report,
        Err(message) => return Response::error(400, message),
    };
    let describe = describe_control(&report, &change);
    let connection = json!({
        "state": report.state, "describe": describe,
        "problems": report.problems, "warnings": report.warnings, "notes": report.notes,
    });
    let succeeded = report.state.is_success();
    let log_id =
        router.record(json!({"dry_run": wanted.dry_run, "succeeded": succeeded, "connections": [connection.clone()]}));
    router.changes.raise();
    let mut body = serde_json::to_value(&report).unwrap_or(Value::Null);
    body["succeeded"] = json!(succeeded);
    body["dry_run"] = json!(wanted.dry_run);
    body["describe"] = json!(describe);
    body["connections"] = json!([connection]);
    body["log_id"] = json!(log_id);
    Response::json(200, &body)
}

/// A change to a Sender and what became of it, in a line: "CAM 1 video (Camera 1): on,
/// to 239.10.1.9:5004: done".
fn describe_control(report: &SenderControl, change: &SenderChange) -> String {
    let mut what = String::from(if change.enable { "on" } else { "off" });
    if !change.destinations.is_empty() {
        let to: Vec<String> = change.destinations.iter().map(Destination::to_string).collect();
        what.push_str(&format!(", to {}", to.join(", ")));
    }
    format!("{}: {what}: {}", report.sender.describe(), report.state.describe())
}

/// The Senders whose streams the page is showing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchRequest {
    senders: Vec<String>,
}

/// Receives the streams of the Senders the page is showing, for another ten seconds:
/// the page asks again every few seconds while it shows them.
fn watch(router: &Router, request: &Request) -> Response {
    let wanted: WatchRequest = match serde_json::from_slice(&request.body) {
        Ok(wanted) => wanted,
        Err(e) => return Response::error(400, format!("not a list of senders: {e}")),
    };
    let mut refused = serde_json::Map::new();
    for id in wanted.senders.iter().take(MOST) {
        let sdp = router.sdp.lock().ok().and_then(|cache| cache.get(id).and_then(|f| f.manifest.sdp.clone()));
        let result = match sdp {
            Some(sdp) => router.previews.watch(id, &sdp),
            None => Err("its SDP file has not been read".into()),
        };
        if let Err(message) = result {
            refused.insert(id.clone(), json!(message));
        }
    }
    let mut body = live_json(router);
    body["refused"] = Value::Object(refused);
    Response::json(200, &body)
}

fn live_json(router: &Router) -> Value {
    let senders: serde_json::Map<String, Value> =
        router.previews.each(|_, status| serde_json::to_value(status).unwrap_or(Value::Null)).into_iter().collect();
    json!({"most": router.previews.most(), "senders": senders})
}

/// What has arrived of each stream being previewed.
fn live(router: &Router) -> Response {
    Response::json(200, &live_json(router))
}

/// The latest picture of a stream being previewed, as a PNG file.
fn picture(router: &Router, request: &Request) -> Response {
    let Some(id) = request.param("sender") else {
        return Response::error(400, "name a sender");
    };
    let Some(picture) = router.previews.picture(&id) else {
        return Response::error(404, "no picture of that sender yet");
    };
    let mut png = Vec::new();
    if let Err(e) = st2110_media::files::write_png(&mut png, picture.width, picture.height, &picture.rgb) {
        return Response::error(500, e.to_string());
    }
    Response { status: 200, content_type: "image/png", headers: Vec::new(), body: png }
}

/// Everything known of a Sender's stream: its IS-04 resources, its SDP file and what the
/// file declares, the checks the file fails, and the Receivers taking it.
fn stream(router: &Router, request: &Request) -> Response {
    let Some(id) = request.param("sender") else {
        return Response::error(400, "name a sender");
    };
    let (mut body, active_url) = match stream_json(router, &id) {
        Ok(read) => read,
        Err(response) => return response,
    };
    // What the Sender says it is doing now, as its Connection API reads it back.
    let active = active_url.map(|url| router.connection_client().get(&url));
    body["active"] = match &active {
        Some(Ok(reply)) if reply.is_success() => reply.body.clone(),
        _ => Value::Null,
    };
    body["active_error"] = match active {
        Some(Ok(reply)) if !reply.is_success() => json!(reply.error()),
        Some(Err(e)) => json!(e.message),
        None => json!("its Device advertises no IS-05 Connection API"),
        Some(Ok(_)) => Value::Null,
    };
    Response::json(200, &body)
}

/// What [`stream`] answers, from the registry as last read, and where the Sender's
/// `/active` endpoint is.
fn stream_json(router: &Router, id: &str) -> Result<(Value, Option<String>), Response> {
    let id = id.to_string();
    let Ok(last) = router.last.lock() else {
        return Err(Response::error(500, "the router failed"));
    };
    let Some(snapshot) = last.as_ref() else {
        return Err(Response::error(409, "the registry has not been read yet"));
    };
    let by_id = |list: &[Value], id: Option<&str>| -> Value {
        id.and_then(|id| list.iter().find(|r| r.get("id").and_then(Value::as_str) == Some(id)).cloned())
            .unwrap_or(Value::Null)
    };
    let sender = by_id(&snapshot.senders, Some(&id));
    if sender.is_null() {
        return Err(Response::error(404, "no such sender"));
    }
    let active_url = routing::find(snapshot, Kind::Sender, &id).ok().and_then(|endpoint| {
        let api = endpoint.connection_api?;
        Some(client::single(&api.href, Kind::Sender, &id, "active"))
    });
    let flow = by_id(&snapshot.flows, sender.get("flow_id").and_then(Value::as_str));
    let source = by_id(&snapshot.sources, flow.get("source_id").and_then(Value::as_str));
    let (device, node) = device_and_node(snapshot, &sender);
    let manifest = snapshot.manifests.get(&id);
    let sdp = manifest.and_then(|m| m.sdp.clone());
    let report = sdp.as_deref().map(st2110_sdp::lint);
    let findings: Vec<Value> = report
        .iter()
        .flat_map(|r| &r.diagnostics)
        .map(|d| json!({"severity": d.severity, "rule": d.rule, "line": d.line, "message": d.message}))
        .collect();
    let receivers: Vec<Value> = snapshot
        .receivers
        .iter()
        .filter(|r| {
            let subscription = r.get("subscription");
            subscription.and_then(|s| s.get("sender_id")).and_then(Value::as_str) == Some(id.as_str())
                && subscription.and_then(|s| s.get("active")).and_then(Value::as_bool) == Some(true)
        })
        .map(|r| json!(text(r, "label").unwrap_or_default()))
        .collect();
    Ok((
        json!({
            "id": id, "device": device, "node": node,
            "sender": sender, "flow": flow, "source": source,
            "sdp_url": manifest.map(|m| m.url.clone()),
            "sdp_error": manifest.and_then(|m| m.error.clone().or_else(|| m.status.filter(|s| !(200..300).contains(s)).map(|s| format!("HTTP {s}")))),
            "sdp": sdp,
            "streams": report.as_ref().map(|r| serde_json::to_value(&r.streams).unwrap_or(Value::Null)),
            "findings": findings,
            "receivers": receivers,
        }),
        active_url,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_only_addresses_and_localhost() {
        for host in ["127.0.0.1:8110", "localhost:8110", "LOCALHOST", "[::1]:8110", "192.168.1.20", "10.0.0.5:80"] {
            assert!(host_allowed(Some(host)), "{host}");
        }
        for host in [
            "evil.example:8110",
            "evil.example",
            "127.0.0.1.nip.io:8110",
            "[::1",
            "",
            "127.0.0.1:",
            "127.0.0.1:80; connect-src *",
            "[::1]x",
        ] {
            assert!(!host_allowed(Some(host)), "{host}");
        }
        assert!(!host_allowed(None));
    }

    fn request(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".into(),
            path: "/api/take".into(),
            query: String::new(),
            headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn takes_connections_only_from_the_page() {
        let json = ("Content-Type", "application/json");
        let host = ("Host", "127.0.0.1:8110");
        assert!(same_origin(&request(&[json, host])).is_ok());
        assert!(same_origin(&request(&[json, host, ("Origin", "http://127.0.0.1:8110")])).is_ok());
        assert!(same_origin(&request(&[json, host, ("Sec-Fetch-Site", "same-origin")])).is_ok());
        assert!(same_origin(&request(&[host, ("Content-Type", "text/plain")])).is_err());
        assert!(same_origin(&request(&[json, host, ("Origin", "http://evil.example")])).is_err());
        assert!(same_origin(&request(&[json, host, ("Origin", "null")])).is_err());
        assert!(same_origin(&request(&[json, host, ("Sec-Fetch-Site", "cross-site")])).is_err());
    }
}
