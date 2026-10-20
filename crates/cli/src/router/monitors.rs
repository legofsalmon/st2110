//! The status monitors of the Senders and Receivers on the page, live (IS-12, BCP-008).
//!
//! For each Device the registry lists with an IS-12 control endpoint, the router reads
//! its monitors once, subscribes to them, and sends the pages each change as it hears
//! it (`monitors`), as BCP-008 asks of a controller: subscribe, never poll. It follows
//! the endpoints only while a page is open, connects again when one drops, and lets go
//! of a Device the registry no longer lists.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_nmos::ncp::{self, client::Connection};
use st2110_nmos::{Snapshot, auth, routing};

use super::Router;

/// How long the router waits for a notification before it looks whether it still
/// follows the Device.
const LISTEN: Duration = Duration::from_secs(1);

/// How long a Device may be quiet before the router pings it.
const QUIET: Duration = Duration::from_secs(15);

/// What the router knows of the monitors.
#[derive(Default)]
pub(crate) struct Monitors {
    /// Each endpoint followed, by its href, with whether it is still wanted.
    followed: Mutex<HashMap<String, Arc<AtomicBool>>>,
    /// Each Sender's and Receiver's monitor as the page shows it, by the Sender's or
    /// Receiver's id, with the endpoint it came from.
    statuses: Mutex<BTreeMap<String, (String, Value)>>,
}

impl Monitors {
    /// The message that tells a page every monitor's status.
    pub(crate) fn message(&self) -> String {
        let statuses = self.statuses.lock().map(|s| s.clone()).unwrap_or_default();
        let monitors: serde_json::Map<String, Value> =
            statuses.into_iter().map(|(id, (_, status))| (id, status)).collect();
        json!({"type": "monitors", "monitors": monitors}).to_string()
    }

    /// Puts what was read at `href`, in place of what was read there before.
    fn put(&self, href: &str, reads: &[Value]) {
        let Ok(mut statuses) = self.statuses.lock() else { return };
        statuses.retain(|_, (from, _)| from != href);
        for read in reads {
            let Some((kind, view)) = st2110_nmos::monitors::view(href, read) else { continue };
            let named = ncp::touchpoint_resources(&read["touchpoints"]);
            let Some((_, id)) = named.iter().find(|(t, _)| *t == kind.as_str()) else { continue };
            let mut status = serde_json::to_value(&view).unwrap_or(Value::Null);
            status["kind"] = json!(kind.as_str());
            statuses.entry((*id).to_string()).or_insert_with(|| (href.to_string(), status));
        }
    }
}

/// Follows every IS-12 endpoint `snapshot` lists that is not followed yet, and lets go
/// of those it no longer lists.
pub(crate) fn follow_all(router: &Arc<Router>, snapshot: &Snapshot) {
    let listed: Vec<String> = routing::ncp_endpoints(snapshot).into_iter().map(|(_, href)| href).collect();
    let Ok(mut followed) = router.monitors.followed.lock() else { return };
    followed.retain(|href, wanted| {
        let keep = listed.contains(href);
        if !keep {
            wanted.store(false, Ordering::Relaxed);
        }
        keep
    });
    for href in listed {
        if followed.contains_key(&href) {
            continue;
        }
        let wanted = Arc::new(AtomicBool::new(true));
        followed.insert(href.clone(), wanted.clone());
        let r = router.clone();
        std::thread::spawn(move || follow(&r, &href, &wanted));
    }
}

/// Follows one endpoint while it is wanted and a page is open, connecting again when
/// it drops.
fn follow(router: &Router, href: &str, wanted: &Arc<AtomicBool>) {
    let mut wait = Duration::from_secs(1);
    let following = || wanted.load(Ordering::Relaxed) && router.pages.count() > 0;
    while following() {
        let started = Instant::now();
        let result = listen(router, href, &following);
        // What is not heard is not shown: the page falls quiet rather than stale.
        router.monitors.put(href, &[]);
        router.pages.send(|_| true, &router.monitors.message());
        if result.is_ok() || !following() {
            break;
        }
        if started.elapsed() > Duration::from_secs(60) {
            wait = Duration::from_secs(1);
        }
        let until = Instant::now() + wait;
        while Instant::now() < until && following() {
            std::thread::sleep(Duration::from_millis(200));
        }
        wait = (wait * 2).min(Duration::from_secs(30));
    }
    if let Ok(mut followed) = router.monitors.followed.lock()
        && followed.get(href).is_some_and(|w| Arc::ptr_eq(w, wanted))
    {
        followed.remove(href);
    }
}

/// Reads the endpoint's monitors, subscribes to them, and passes each change on, until
/// it is no longer followed (`Ok`) or the connection fails.
fn listen(router: &Router, href: &str, following: &dyn Fn() -> bool) -> io::Result<()> {
    let bearer = match router.token.as_ref().filter(|_| auth::may_send_to(href)).map(auth::Token::bearer) {
        Some(Ok(bearer)) => Some(format!("Bearer {bearer}")),
        Some(Err(e)) => return Err(io::Error::other(e.message)),
        None => None,
    };
    let headers: Vec<(&str, &str)> = bearer.iter().map(|b| ("Authorization", b.as_str())).collect();
    let mut device = Connection::open(href, &headers, router.timeout)?;
    let mut reads = device.monitors()?;
    let oids: Vec<u64> = reads.iter().filter_map(|r| r["oid"].as_u64()).collect();
    device.subscribe(&oids)?;
    router.monitors.put(href, &reads);
    router.pages.send(|_| true, &router.monitors.message());
    device.set_read_timeout(Some(LISTEN))?;
    let mut heard = Instant::now();
    loop {
        if !following() {
            device.close();
            return Ok(());
        }
        match device.next_change() {
            Ok(Some(change)) => {
                heard = Instant::now();
                if reads.iter_mut().any(|read| ncp::client::apply(read, &change)) {
                    router.monitors.put(href, &reads);
                    router.pages.send(|_| true, &router.monitors.message());
                }
            }
            Ok(None) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the Device closed it")),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if heard.elapsed() > QUIET {
                    device.ping()?;
                    heard = Instant::now();
                }
            }
            Err(e) => return Err(e),
        }
    }
}
