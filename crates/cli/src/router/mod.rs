//! `st2110 router`: a router panel in the browser. The page shows which Senders each
//! Receiver can take as a crosspoint grid, and a click connects them through IS-05.
//!
//! This command serves the page, and does the work it asks for: it reads the registry
//! and makes connections with `st2110 connect`'s controller, salvos and rollbacks
//! included. The browser talks only to it, so devices need not allow a page from
//! another site to send them requests, and no video passes through the browser.
//!
//! Anyone who can reach the page can make connections. It listens on this machine's
//! loopback address unless told otherwise, and answers only requests addressed to an
//! IP address or `localhost`, and connection requests sent from the page itself, so
//! another web site cannot make them through a visitor's browser.

mod demo;
mod http;
mod preview;
mod signal;

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};
use st2110_connect::client::{self, ConnectionClient};
use st2110_connect::controller::{self, Route, Settings, Take};
use st2110_nmos::client::{Options, QueryClient};
use st2110_nmos::{Manifest, Snapshot, routing};

use self::demo::Facility;
use self::http::{Request, Response};
use self::preview::Previews;
use crate::seconds;

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
            (format!("{base}/x-nmos/query/v1.3/"), Some(Mutex::new(Facility::new(&base, args.tai_utc))))
        }
        _ => return Err(Failure::Usage("give a registry's Query API URL, or --demo".into())),
    };
    let router = Arc::new(Router {
        registry,
        demo,
        timeout,
        settings,
        last: Mutex::new(None),
        sdp: Mutex::default(),
        taking: Mutex::new(()),
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

fn handle(router: &Router, stream: &TcpStream) {
    let Ok(Some(request)) = http::read(stream) else {
        return;
    };
    let response = answer(router, &request);
    let _ = http::write(stream, &response);
}

/// Whether a `Host` header names this server by an IP address or `localhost`. A page
/// from another site that has pointed its own name at this machine, to read from it or
/// send it requests as if from that site, sends its name instead.
fn host_allowed(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(ip, _)| ip),
        None => Some(host.rsplit_once(':').map_or(host, |(name, port)| if port.is_empty() { "" } else { name })),
    };
    name.is_some_and(|name| name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().is_ok())
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
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; \
                     img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                        .into(),
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
        ("POST", "/api/watch") => match same_origin(request) {
            Ok(()) => watch(router, request),
            Err(message) => Response::error(403, message),
        },
        ("GET", "/api/live") => live(router),
        ("GET", "/api/preview") => picture(router, request),
        ("GET", "/api/stream") => stream(router, request),
        (
            _,
            "/" | "/api/state" | "/api/why" | "/api/take" | "/api/watch" | "/api/live" | "/api/preview" | "/api/stream",
        ) => Response::error(405, "not with that method"),
        _ => Response::error(404, "nothing here"),
    }
}

impl Router {
    fn query_client(&self, fetch_sdp: bool) -> Result<QueryClient, String> {
        let options =
            Options { timeout: self.timeout, fetch_sdp, env_proxy: self.demo.is_none(), ..Options::default() };
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
        ConnectionClient::new(&client::Options { timeout: self.timeout, env_proxy: self.demo.is_none() })
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

/// The registry, as the page shows it: every Sender, and every Receiver with the
/// Senders it can take and the one it takes now.
fn state(router: &Router) -> Response {
    let read = router.query_client(false).and_then(|registry| {
        let mut snapshot = registry.snapshot().map_err(|e| e.to_string())?;
        router.add_sdp(&registry, &mut snapshot);
        Ok(snapshot)
    });
    let snapshot = match read {
        Ok(snapshot) => snapshot,
        Err(message) => return Response::error(502, format!("reading the registry: {message}")),
    };
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
            json!({
                "id": s.id, "label": s.label, "device": device, "node": node,
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
        "senders": senders, "receivers": receivers,
    });
    if let Ok(mut last) = router.last.lock() {
        *last = Some(snapshot);
    }
    Response::json(200, &body)
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

/// Makes the connections the page asks for, together, as `st2110 connect --salvo` does.
fn take(router: &Router, request: &Request) -> Response {
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
    let Ok(last) = router.last.lock() else {
        return Response::error(500, "the router failed");
    };
    let Some(snapshot) = last.as_ref() else {
        return Response::error(409, "the registry has not been read yet");
    };
    let by_id = |list: &[Value], id: Option<&str>| -> Value {
        id.and_then(|id| list.iter().find(|r| r.get("id").and_then(Value::as_str) == Some(id)).cloned())
            .unwrap_or(Value::Null)
    };
    let sender = by_id(&snapshot.senders, Some(&id));
    if sender.is_null() {
        return Response::error(404, "no such sender");
    }
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
    Response::json(
        200,
        &json!({
            "id": id, "device": device, "node": node,
            "sender": sender, "flow": flow, "source": source,
            "sdp_url": manifest.map(|m| m.url.clone()),
            "sdp_error": manifest.and_then(|m| m.error.clone().or_else(|| m.status.filter(|s| !(200..300).contains(s)).map(|s| format!("HTTP {s}")))),
            "sdp": sdp,
            "streams": report.as_ref().map(|r| serde_json::to_value(&r.streams).unwrap_or(Value::Null)),
            "findings": findings,
            "receivers": receivers,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_only_addresses_and_localhost() {
        for host in ["127.0.0.1:8110", "localhost:8110", "LOCALHOST", "[::1]:8110", "192.168.1.20", "10.0.0.5:80"] {
            assert!(host_allowed(Some(host)), "{host}");
        }
        for host in ["evil.example:8110", "evil.example", "127.0.0.1.nip.io:8110", "[::1", ""] {
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
