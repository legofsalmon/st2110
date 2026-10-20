//! Live updates: the page hears of each change over a WebSocket, rather than asking every
//! few seconds, and the router hears of each change in the registry the same way.
//!
//! The page connects to `/api/events`. The router sends it what it last read straight
//! away, then the registry again whenever it changes (`state`), what has arrived of each
//! stream being previewed (`live`), and each connection made from any page (`log`).
//!
//! To know when the registry changes, the router subscribes to its Query API (IS-04 Query
//! API: Subscriptions) for each type of resource, and reads the registry again whenever
//! one of them speaks. A registry that offers no subscriptions, or one that cannot be
//! reached, is read every three seconds instead, while a page is open; one that does is
//! read again every 30 seconds too, in case a change went unheard.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_nmos::ws::{self, Frame};

use super::{Router, live_json, state_json};
use crate::http::Request;

/// The resources the router subscribes to: everything the page shows.
const RESOURCES: [&str; 6] = ["/nodes", "/devices", "/sources", "/flows", "/senders", "/receivers"];

/// How often a registry without subscriptions is read while a page is open.
const READ_EVERY: Duration = Duration::from_secs(3);

/// How often a registry with subscriptions is read anyway.
const CHECK_EVERY: Duration = Duration::from_secs(30);

/// How often previews' progress goes to the pages.
const LIVE_EVERY: Duration = Duration::from_millis(500);

/// How long a page's WebSocket may be silent before the router pings it, and a
/// subscription's before the router pings the registry.
const QUIET: Duration = Duration::from_secs(15);

/// The most pages connected at once.
const MOST_PAGES: usize = 64;

/// The largest message a page may send: it sends only pongs and closes.
const PAGE_MESSAGE_LIMIT: usize = 4 << 10;

/// WebSocket connections to push messages to, each with its topic: a page's, or a
/// subscription's resource path on the demo registry.
#[derive(Default)]
pub(crate) struct Hub {
    next: AtomicU64,
    clients: Mutex<Vec<Arc<Client>>>,
}

pub(crate) struct Client {
    id: u64,
    topic: String,
    stream: Mutex<TcpStream>,
}

impl Hub {
    /// Adds a connection, unless there are `most` already.
    pub(crate) fn add(&self, topic: &str, stream: &TcpStream, most: usize) -> Option<Arc<Client>> {
        let mut clients = self.clients.lock().ok()?;
        if clients.len() >= most {
            return None;
        }
        let stream = stream.try_clone().ok()?;
        // A page that stops reading is dropped rather than holding everyone else up.
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
        let client = Arc::new(Client {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            topic: topic.into(),
            stream: stream.into(),
        });
        clients.push(client.clone());
        Some(client)
    }

    fn remove(&self, id: u64) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.retain(|c| c.id != id);
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.clients.lock().map_or(0, |c| c.len())
    }

    /// Sends `text` to every connection whose topic `wanted` picks, dropping any that
    /// cannot take it.
    pub(crate) fn send(&self, wanted: impl Fn(&str) -> bool, text: &str) {
        let clients: Vec<Arc<Client>> = self.clients.lock().map(|c| c.clone()).unwrap_or_default();
        for client in clients.iter().filter(|c| wanted(&c.topic)) {
            if client.send(&Frame::Text(text.to_string())).is_err() {
                self.remove(client.id);
            }
        }
    }

    /// Answers the connection's pings and closes until it goes, then forgets it.
    pub(crate) fn hold(&self, client: &Client, stream: &TcpStream) {
        let _ = stream.set_read_timeout(Some(QUIET));
        let mut reader = stream;
        let mut pinged = false;
        loop {
            match ws::read_frame(&mut reader, PAGE_MESSAGE_LIMIT) {
                Ok(Frame::Ping(payload)) => {
                    if client.send(&Frame::Pong(payload)).is_err() {
                        break;
                    }
                }
                Ok(Frame::Close(code)) => {
                    let _ = client.send(&Frame::Close(code.or(Some(1000))));
                    break;
                }
                Ok(_) => pinged = false,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) && !pinged => {
                    // Quiet for a while: a ping, which a browser answers on its own.
                    pinged = true;
                    if client.send(&Frame::Ping(Vec::new())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        self.remove(client.id);
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

impl Client {
    pub(crate) fn send(&self, frame: &Frame) -> io::Result<()> {
        let mut stream = self.stream.lock().map_err(|_| io::Error::other("the connection failed"))?;
        ws::write_frame(&mut *stream, frame, None)
    }
}

/// Whether a request asks to become a WebSocket.
pub(crate) fn is_upgrade(request: &Request) -> bool {
    request.header("Upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        && request.header("Connection").is_some_and(|c| c.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

/// Answers a WebSocket handshake: `Err` with the status to refuse it with, when it is
/// not one this server takes.
pub(crate) fn accept(mut stream: &TcpStream, request: &Request) -> Result<(), (u16, String)> {
    if request.method != "GET" || !is_upgrade(request) {
        return Err((400, "not a WebSocket request".into()));
    }
    if request.header("Sec-WebSocket-Version") != Some("13") {
        return Err((426, "WebSocket version 13 only".into()));
    }
    let Some(key) = request.header("Sec-WebSocket-Key") else {
        return Err((400, "no Sec-WebSocket-Key".into()));
    };
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        ws::accept_key(key)
    );
    stream.write_all(head.as_bytes()).and_then(|()| stream.flush()).map_err(|e| (500, e.to_string()))
}

/// Tells the threads below that something may have changed.
#[derive(Default)]
pub(crate) struct Signal {
    raised: Mutex<bool>,
    wake: Condvar,
}

impl Signal {
    pub(crate) fn raise(&self) {
        if let Ok(mut raised) = self.raised.lock() {
            *raised = true;
            self.wake.notify_all();
        }
    }

    /// Waits up to `timeout` for a change, and says whether there was one.
    fn wait(&self, timeout: Duration) -> bool {
        let Ok(raised) = self.raised.lock() else {
            std::thread::sleep(timeout);
            return false;
        };
        let (mut raised, _) = self.wake.wait_timeout_while(raised, timeout, |r| !*r).unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *raised)
    }
}

/// What the pages have been sent of the registry.
#[derive(Default)]
pub(crate) struct Sent {
    /// The state last sent, without the time it was read, to tell a change by.
    state: Option<Value>,
    /// The whole message last sent, for a page that connects.
    message: Option<String>,
    /// The error last sent, until the registry answers again.
    error: Option<String>,
}

/// A page's `/api/events`: sends it what is known, then holds it open.
pub(crate) fn page(router: &Arc<Router>, stream: &TcpStream, request: &Request) {
    if let Err((status, message)) = accept(stream, request) {
        let _ = crate::http::write(stream, &crate::http::Response::error(status, message));
        return;
    }
    let Some(client) = router.pages.add("page", stream, MOST_PAGES) else {
        let _ = ws::write_frame(&mut &*stream, &Frame::Close(Some(1013)), None);
        return;
    };
    let log = router.log.lock().map(|l| l.iter().rev().take(50).rev().cloned().collect::<Vec<_>>()).unwrap_or_default();
    let hello = json!({"type": "hello", "log": log, "subscribed": router.subscribed(), "auth": router.auth_note()});
    let mut ok = client.send(&Frame::Text(hello.to_string())).is_ok();
    let known = router.sent.lock().ok().and_then(|s| s.error.clone().or(s.message.clone()));
    if let Some(known) = known {
        ok = ok && client.send(&Frame::Text(known)).is_ok();
    }
    // Read it again for this page, so that what it has is current.
    router.changes.raise();
    if ok {
        router.pages.hold(&client, stream);
    } else {
        router.pages.remove(client.id);
    }
}

/// Starts the threads that keep the pages up to date.
pub(crate) fn start(router: &Arc<Router>) {
    let r = router.clone();
    std::thread::spawn(move || read_registry(&r));
    let r = router.clone();
    std::thread::spawn(move || send_live(&r));
}

/// Reads the registry when it changes, or every few seconds without subscriptions, while
/// a page is open, and sends the pages what changed.
fn read_registry(router: &Arc<Router>) {
    let mut following = false;
    let mut last_read = Instant::now() - CHECK_EVERY;
    loop {
        if router.pages.count() == 0 {
            router.changes.wait(Duration::from_millis(500));
            continue;
        }
        if !following {
            following = true;
            for path in RESOURCES {
                let r = router.clone();
                std::thread::spawn(move || follow(&r, path));
            }
        }
        let every = if router.subscribed() { CHECK_EVERY } else { READ_EVERY };
        let changed = router.changes.wait(every.saturating_sub(last_read.elapsed()));
        if !changed && last_read.elapsed() < every {
            continue;
        }
        // Changes come in bursts, such as a salvo's: one read for all of them.
        std::thread::sleep(Duration::from_millis(100));
        router.changes.wait(Duration::ZERO);
        last_read = Instant::now();
        broadcast_state(router);
    }
}

/// Reads the registry, and sends the pages the result when it differs from what they
/// have, or just when it was read.
pub(crate) fn broadcast_state(router: &Router) {
    let read = state_json(router);
    let Ok(mut sent) = router.sent.lock() else { return };
    match read {
        Ok(mut body) => {
            let mut without_time = body.clone();
            without_time["read_at"] = Value::Null;
            body["type"] = json!("state");
            body["subscribed"] = json!(router.subscribed());
            let message = body.to_string();
            if sent.state.as_ref() != Some(&without_time) || sent.error.is_some() {
                router.pages.send(|_| true, &message);
                sent.state = Some(without_time);
            } else {
                let read = json!({"type": "read", "read_at": body["read_at"], "subscribed": router.subscribed()});
                router.pages.send(|_| true, &read.to_string());
            }
            sent.message = Some(message);
            sent.error = None;
        }
        Err(message) => {
            let error = json!({"type": "error", "message": message}).to_string();
            if sent.error.as_ref() != Some(&error) {
                router.pages.send(|_| true, &error);
                sent.error = Some(error);
            }
        }
    }
}

/// Sends the pages what has arrived of each stream being previewed.
fn send_live(router: &Router) {
    let mut empty = true;
    loop {
        std::thread::sleep(LIVE_EVERY);
        if router.pages.count() == 0 {
            continue;
        }
        let mut live = live_json(router);
        let now_empty = live["senders"].as_object().is_none_or(serde_json::Map::is_empty);
        if now_empty && empty {
            continue;
        }
        empty = now_empty;
        live["type"] = json!("live");
        router.pages.send(|_| true, &live.to_string());
    }
}

/// Follows one subscription to the registry for as long as the router runs, connecting
/// again when it drops.
fn follow(router: &Router, path: &'static str) {
    let mut wait = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        let result = subscribe(router, path);
        if let Err(Stop::Unsupported(why)) = &result {
            router.note_subscription(path, Some(why.clone()));
            // A registry without subscriptions is read every few seconds instead; it
            // may gain them after an upgrade.
            std::thread::sleep(Duration::from_secs(300));
            continue;
        }
        if let Err(Stop::Failed(why)) = &result {
            router.note_subscription(path, Some(why.clone()));
        }
        if started.elapsed() > Duration::from_secs(60) {
            wait = Duration::from_secs(1);
        }
        std::thread::sleep(wait);
        wait = (wait * 2).min(Duration::from_secs(30));
    }
}

enum Stop {
    /// The registry offers no subscriptions.
    Unsupported(String),
    Failed(String),
}

fn subscribe(router: &Router, path: &str) -> Result<(), Stop> {
    let registry = router.query_client(false).map_err(Stop::Failed)?;
    let subscription = registry.subscribe(path, 100).map_err(|e| {
        if e.message.starts_with("HTTP 404") || e.message.starts_with("HTTP 405") || e.message.starts_with("HTTP 501") {
            Stop::Unsupported(e.to_string())
        } else {
            Stop::Failed(e.to_string())
        }
    })?;
    let headers = registry.websocket_headers(&subscription.ws_href).map_err(|e| Stop::Failed(e.to_string()))?;
    let pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let mut socket = ws::connect(&subscription.ws_href, &pairs, router.timeout).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            registry.token_refused(&headers);
        }
        Stop::Failed(format!("{}: {e}", subscription.ws_href))
    })?;
    let _ = socket.set_read_timeout(Some(QUIET));
    router.note_subscription(path, None);
    let _connected = Connected(router, path);
    let mut pinged = false;
    loop {
        match socket.read_any() {
            Ok(Frame::Text(_)) => {
                pinged = false;
                router.changes.raise();
            }
            Ok(Frame::Close(_)) => return Err(Stop::Failed("the registry closed the subscription".into())),
            Ok(_) => pinged = false,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) && !pinged => {
                pinged = true;
                socket.send(&Frame::Ping(Vec::new())).map_err(|e| Stop::Failed(e.to_string()))?;
            }
            Err(e) => return Err(Stop::Failed(format!("the subscription's WebSocket: {e}"))),
        }
    }
}

/// Marks a subscription as no longer connected when it ends, however it ends.
struct Connected<'a>(&'a Router, &'a str);

impl Drop for Connected<'_> {
    fn drop(&mut self) {
        self.0.note_subscription(self.1, Some("disconnected".into()));
        // What changed while it was down is read now.
        self.0.changes.raise();
    }
}

/// Which subscriptions are connected, and why the others are not.
#[derive(Default)]
pub(crate) struct Subscriptions {
    connected: AtomicUsize,
    down: Mutex<HashMap<String, Option<String>>>,
}

impl Subscriptions {
    pub(crate) fn note(&self, path: &str, problem: Option<String>) {
        let Ok(mut down) = self.down.lock() else { return };
        down.insert(path.to_string(), problem);
        let connected = down.values().filter(|p| p.is_none()).count();
        self.connected.store(connected, Ordering::Relaxed);
    }

    /// Whether every subscription is connected.
    pub(crate) fn all(&self) -> bool {
        self.connected.load(Ordering::Relaxed) == RESOURCES.len()
    }
}
