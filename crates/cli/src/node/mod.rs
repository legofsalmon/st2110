//! NMOS Nodes of this program's own: `st2110 send --nmos` and `st2110 receive --nmos`
//! each run one, with one Device and the one Sender, or Receiver, the command runs.
//!
//! The Node serves an IS-04 v1.3 Node API and an IS-05 v1.2 Connection API
//! ([`connection`]) on one port, and registers its resources with a registry's
//! Registration API, as IS-04 v1.3 Registered Operation has it: with the registry
//! named, or the one DNS-SD finds (`_nmos-register._tcp`), heartbeats every 5 seconds,
//! everything registered again when the registry has forgotten the Node, another
//! registry tried when it does not answer, and the resources deleted when the command
//! ends. An IS-10 token is sent where the registry asks for one; the Node's own APIs
//! ask for none.
//!
//! Where there is no registry to register with, none found by DNS-SD or none that
//! answers, the Node advertises its Node API by multicast DNS for peer-to-peer
//! discovery (IS-04 v1.3 Discovery: Peer to Peer), with the version counters that
//! tell a controller when to read it again, and DNS-SD is asked again every 30
//! seconds; once registered, it says goodbye. Its Node API also takes IS-04's
//! deprecated `/target`, as an IS-05 immediate activation.
//!
//! An activation through IS-05 changes the running stream: a Sender sends to the new
//! destination, or stops and starts with `master_enable` ([`sending`]), and a Receiver
//! receives what the transport file and parameters describe ([`receiving`]). The
//! registry hears of each, as IS-04 asks.
//!
//! The Device also has an IS-12 control endpoint ([`ncp`]) with a BCP-008 status
//! monitor of the Sender or Receiver ([`monitor`]), which `st2110 send` and `st2110
//! receive` feed with what the stream does.

pub(crate) mod connection;
pub(crate) mod mapping;
pub(crate) mod monitor;
mod ncp;
mod receiving;
mod resources;
mod sending;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_connect::client::ConnectionClient;
use st2110_connect::{Activation, Constraints, Plan};
use st2110_discover::nmos::{self as discovery, Counters};
use st2110_discover::responder::{self, Instance, Responder};
use st2110_media::describe::{Clock, Description};
use st2110_nmos::Kind;
use st2110_nmos::auth::SCOPES;
use st2110_nmos::client::{Options, RegistrationClient};
use st2110_ptp::PtpTime;

pub(crate) use self::receiving::{Receiving, Tuning};
pub(crate) use self::sending::{Sending, Switch, Switched};

use self::connection::{Control, Endpoint, Side, error, tai};
use self::resources::{CONNECTION_VERSION, Ids, Place};
use crate::find::{self, LookArgs};
use crate::http::{self, Request, Response};

/// How often the Node tells the registry it is still there (IS-04 v1.3 Behaviour:
/// Registration, Heartbeating).
const HEARTBEAT: Duration = Duration::from_secs(5);

/// How long one request to the registry may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait before asking a registry named again, when it did not answer.
const RETRY: Duration = Duration::from_secs(5);

/// How long to wait before asking DNS-SD again, when it found no registry.
const LOOK_AGAIN: Duration = Duration::from_secs(30);

/// How often scheduled activations are looked for.
const TICK: Duration = Duration::from_millis(10);

/// The options that make `st2110 send` or `st2110 receive` an NMOS Node.
#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct NodeArgs {
    /// Run as an NMOS Node: serve an IS-04 Node API and an IS-05 Connection API for the
    /// Sender or Receiver, and register it with the registry at --nmos=URL, or with the
    /// one DNS-SD finds when no URL is given; with no registry, advertise it by multicast
    /// DNS for controllers to find peer to peer. A controller can then move the stream,
    /// or turn it off and on.
    #[arg(
        long,
        value_name = "URL",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        conflicts_with = "pcap",
        help_heading = "NMOS"
    )]
    pub nmos: Option<String>,
    /// The port to serve the Node API and the Connection API on, on every interface;
    /// one the system picks when omitted.
    #[arg(long, value_name = "PORT", default_value_t = 0, requires = "nmos", help_heading = "NMOS")]
    pub nmos_port: u16,
    /// The Sender's or Receiver's label in the registry: the session name for a Sender,
    /// and `st2110 receive on <this machine>` for a Receiver, when omitted.
    #[arg(long, value_name = "TEXT", requires = "nmos", help_heading = "NMOS")]
    pub label: Option<String>,
    #[command(flatten, next_help_heading = "NMOS")]
    pub auth: crate::auth::Auth,
}

/// What the Node's one Sender or Receiver does when it is activated.
pub(crate) trait Role: Send {
    fn side(&self) -> Side;

    /// Whether staged parameters could be activated: an `Err` says why not.
    fn check(&self, staged: &Value) -> Result<(), String>;

    /// Makes the active parameters take effect, filling in what only that finds out,
    /// such as the port a Sender sends from.
    fn activate(&mut self, active: &mut Value);

    /// A Sender's transport file.
    fn transport_file(&self) -> Option<String> {
        None
    }
}

/// What the Node offers.
pub(crate) enum Offer<'a> {
    /// A Sender of this stream, each leg's source the interface it goes from.
    Sender(&'a Description),
    /// A Receiver of video, or of audio, with this many legs.
    Receiver { video: bool, legs: usize },
}

/// A Node that is running: its APIs served, and registering.
pub(crate) struct Node {
    shared: Arc<Shared>,
    registering: Option<thread::JoinHandle<Option<String>>>,
    /// The Node API's URL.
    #[cfg(test)]
    api: String,
}

struct Shared {
    state: Mutex<State>,
    /// Woken when the state changes, or the Node is to stop.
    wake: Condvar,
    /// The controllers connected to the IS-12 endpoint.
    sessions: ncp::Sessions,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tells the IS-12 controllers what changed in the Device model.
    fn notify(&self) {
        let changes = {
            let mut state = self.lock();
            if !state.ncp.has_changes() {
                return;
            }
            state.ncp.take_changes()
        };
        self.sessions.notify(&changes);
    }
}

/// How often the monitor measures and reports.
const MONITOR_TICK: Duration = Duration::from_millis(500);

/// What a Sender's monitor reads its counts from.
pub(crate) type Watch = Box<dyn FnMut() -> monitor::Observation + Send>;

/// What the Node knows.
struct State {
    /// Its resources, in the order they are registered: the Node, the Device, the
    /// Source and Flow of a Sender, and the Sender or Receiver.
    resources: Vec<(Kind, Value)>,
    side: Side,
    endpoints: BTreeMap<String, Endpoint>,
    /// The other side's, which has none.
    none: BTreeMap<String, Endpoint>,
    role: Box<dyn Role>,
    tai_utc: i32,
    /// Whether the Sender or Receiver changed since it was last registered.
    changed: bool,
    stopping: bool,
    /// The IS-12 Device model, with the monitor.
    ncp: ncp::Model,
    /// The addresses of the interfaces the stream uses, for the monitor's link status.
    addresses: Vec<Ipv4Addr>,
    /// Where a Sender's monitor reads its counts.
    watch: Option<Watch>,
    /// The version counters advertised peer to peer.
    counters: Counters,
    /// The multicast DNS responder that advertises the Node while there is no registry
    /// to register with.
    advertising: Option<Responder>,
}

impl State {
    fn endpoint_resource(&mut self) -> &mut Value {
        &mut self.resources.last_mut().expect("a Sender or Receiver").1
    }

    /// The text pairs the Node advertises peer to peer: it serves IS-04 v1.3 over HTTP,
    /// and asks for no token.
    fn txt(&self) -> Vec<(String, String)> {
        self.counters.txt("http", &["v1.3"], false)
    }
}

impl Control for State {
    fn endpoints(&mut self, side: Side) -> &mut BTreeMap<String, Endpoint> {
        if side == self.side { &mut self.endpoints } else { &mut self.none }
    }

    fn now(&self) -> PtpTime {
        crate::timing::now(self.tai_utc).unwrap_or_else(|_| PtpTime::from_utc(0, 0).expect("the epoch"))
    }

    fn check(&self, _side: Side, _id: &str, staged: &Value) -> Result<(), String> {
        self.role.check(staged)
    }

    fn activated(&mut self, side: Side, id: &str, at: PtpTime) {
        let Some(endpoint) = self.endpoints.get_mut(id) else { return };
        self.role.activate(&mut endpoint.active);
        let active = &endpoint.active;
        let enabled = active["master_enable"] == true;
        let subscription = match side {
            // A Sender names its Receiver only while active (IS-04 v1.3 Behaviour: Nodes).
            Side::Sender => json!({
                "receiver_id": if enabled { active["receiver_id"].clone() } else { Value::Null },
                "active": enabled,
            }),
            Side::Receiver => json!({"sender_id": active["sender_id"], "active": enabled}),
        };
        self.ncp.monitor.activate(enabled, Instant::now());
        let resource = self.endpoint_resource();
        resource["subscription"] = subscription;
        resource["version"] = json!(tai(at));
        self.changed = true;
        self.counters.bump(match side {
            Side::Sender => Kind::Sender,
            Side::Receiver => Kind::Receiver,
        });
        if let Some(responder) = &self.advertising {
            responder.set_txt(self.txt());
        }
    }

    fn transport_file(&self, id: &str) -> Option<String> {
        self.endpoints.contains_key(id).then(|| self.role.transport_file()).flatten()
    }

    fn transport_type(&self, side: Side, id: &str) -> Option<String> {
        let (_, resource) = self.resources.last()?;
        (side == self.side && resource["id"] == id).then(|| resource["transport"].as_str().map(str::to_string))?
    }
}

/// This machine's name, for the Node's `hostname` and the ids.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            let output = std::process::Command::new("hostname").output().ok()?;
            String::from_utf8(output.stdout).ok()
        })
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// The interface with `address`, and its MAC address, written as IS-04 writes it. Only
/// Linux shows the MAC address; elsewhere one is made up from the IPv4 address, marked
/// as locally administered.
fn interface(address: Ipv4Addr) -> (String, String) {
    let name = st2110_discover::interfaces()
        .into_iter()
        .find(|i| i.address == address)
        .map_or_else(|| format!("if-{address}"), |i| i.name);
    let mac = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .ok()
        .map(|m| m.trim().to_ascii_lowercase().replace(':', "-"))
        .filter(|m| m.len() == 17)
        .unwrap_or_else(|| {
            let [a, b, c, d] = address.octets();
            format!("02-00-{a:02x}-{b:02x}-{c:02x}-{d:02x}")
        });
    (name, mac)
}

/// The address this machine reaches `to` from, by the routing table.
pub(crate) fn address_towards(to: SocketAddrV4) -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect(to).ok()?;
    match probe.local_addr().ok()? {
        std::net::SocketAddr::V4(a) if !a.ip().is_unspecified() => Some(*a.ip()),
        _ => None,
    }
}

/// The address a Receiver's Node is at, when no interface is given: the one this
/// machine reaches the registry named from, or the one multicast goes out from.
pub(crate) fn default_address(args: &NodeArgs) -> Ipv4Addr {
    let registry = args.nmos.as_deref().filter(|u| !u.is_empty()).and_then(|url| {
        let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
        let host = rest.split('/').next()?;
        let with_port = if host.contains(':') { host.to_string() } else { format!("{host}:80") };
        with_port.to_socket_addrs().ok()?.find_map(|a| match a {
            std::net::SocketAddr::V4(a) => Some(a),
            std::net::SocketAddr::V6(_) => None,
        })
    });
    let to = registry.unwrap_or(st2110_discover::MDNS);
    address_towards(to).unwrap_or(Ipv4Addr::LOCALHOST)
}

impl Node {
    /// Starts the Node: serves its APIs, at the address of `addresses[0]`, the
    /// interface of the first leg, and starts registering. `endpoint` and `role` are
    /// the Sender's or Receiver's.
    pub(crate) fn start(
        args: &NodeArgs,
        offer: &Offer,
        addresses: &[Ipv4Addr],
        endpoint: Endpoint,
        role: Box<dyn Role>,
        tai_utc: i32,
    ) -> Result<Self, String> {
        let registry = args.nmos.clone().unwrap_or_default();
        if !registry.is_empty() {
            let lower = registry.to_ascii_lowercase();
            if !lower.starts_with("http://") && !lower.starts_with("https://") {
                return Err(format!("--nmos={registry} is not a registry's http:// or https:// URL"));
            }
        }
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, args.nmos_port))
            .map_err(|e| format!("--nmos-port {}: {e}", args.nmos_port))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let host = addresses.first().copied().unwrap_or(Ipv4Addr::LOCALHOST);
        let name = hostname();
        let mut interfaces: Vec<(String, String)> = Vec::new();
        let mut bindings = Vec::new();
        for &address in addresses {
            let found = interface(address);
            bindings.push(found.0.clone());
            if !interfaces.contains(&found) {
                interfaces.push(found);
            }
        }
        let place = Place { host, port, hostname: name.clone(), interfaces };
        let now = crate::timing::now(tai_utc)?;
        let version = tai(now);
        let (seed, label) = match offer {
            Offer::Sender(description) => {
                let to: Vec<String> = description.legs.iter().map(|l| l.destination.to_string()).collect();
                (
                    format!("{name} send {}", to.join(" ")),
                    args.label.clone().unwrap_or_else(|| description.name.clone()),
                )
            }
            Offer::Receiver { .. } => {
                // The same ids each run only on a port given.
                let run = if args.nmos_port == 0 { format!("{}", now.nanos()) } else { args.nmos_port.to_string() };
                (
                    format!("{name} receive {run}"),
                    args.label.clone().unwrap_or_else(|| format!("st2110 receive on {name}")),
                )
            }
        };
        let ids = Ids::from_seed(&seed);
        let clock = match offer {
            Offer::Sender(description) => description.clock.clone(),
            Offer::Receiver { .. } => None::<Clock>,
        };
        let mut resources = vec![
            (Kind::Node, resources::node(&ids, &place, &version, &name, clock.as_ref())),
            (Kind::Device, resources::device(&ids, &place, &version, &label)),
        ];
        match offer {
            Offer::Sender(description) => {
                let (source, flow) = resources::source_and_flow(&ids, &version, &label, description);
                let enabled = endpoint.active["master_enable"] == true;
                let sender = resources::sender(&ids, &place, &version, &label, description, &bindings, enabled);
                resources.extend([(Kind::Source, source), (Kind::Flow, flow), (Kind::Sender, sender)]);
            }
            Offer::Receiver { video, legs } => {
                let bindings: Vec<String> = (0..*legs).map(|i| bindings[i.min(bindings.len() - 1)].clone()).collect();
                let enabled = endpoint.active["master_enable"] == true;
                let receiver = resources::receiver(&ids, &version, &label, *video, &bindings, enabled);
                resources.push((Kind::Receiver, receiver));
            }
        }
        let side = role.side();
        let sync = match &clock {
            Some(Clock::Ptp { grandmaster, domain }) => {
                monitor::Sync::ptp(&grandmaster.to_string().to_ascii_lowercase(), *domain)
            }
            _ => monitor::Sync::internal(),
        };
        let identity =
            ncp::Identity { side, label: &label, device_id: &ids.device, endpoint_id: &ids.endpoint, hostname: &name };
        let active = endpoint.active["master_enable"] == true;
        let model = ncp::Model::new(&identity, &sync, active, Instant::now());
        let state = State {
            resources,
            side,
            endpoints: BTreeMap::from([(ids.endpoint.clone(), endpoint)]),
            none: BTreeMap::new(),
            role,
            tai_utc,
            changed: false,
            stopping: false,
            ncp: model,
            addresses: addresses.to_vec(),
            watch: None,
            counters: Counters::default(),
            advertising: None,
        };
        let shared =
            Arc::new(Shared { state: Mutex::new(state), wake: Condvar::new(), sessions: ncp::Sessions::default() });
        // The token, and the registry, are found before anything is served, so that
        // what goes wrong with them is said first.
        let mut auth = args.auth.clone();
        if auth.scope == SCOPES {
            auth.scope = "registration".into();
        }
        let token = auth.token(TIMEOUT, true)?;
        let options = Options { timeout: TIMEOUT, token, ..Options::default() };
        let finder = if registry.is_empty() { Finder::Look(args.auth.look.clone()) } else { Finder::Given(registry) };
        let api = format!("http://{host}:{port}/x-nmos/node/v1.3/");
        eprintln!(
            "NMOS: {} {} at {api}, its Connection API at http://{host}:{port}/x-nmos/connection/{CONNECTION_VERSION}/, \
             its IS-12 control at ws://{host}:{port}{}/",
            side.name(),
            ids.endpoint,
            ncp::PATH,
        );
        let served = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let shared = served.clone();
                thread::spawn(move || handle(&shared, &stream));
            }
        });
        let ticking = shared.clone();
        thread::spawn(move || tick(&ticking));
        let advert = Instance {
            service: discovery::NODE.into(),
            name: label.clone(),
            host: format!("{}-nmos-{port}", responder::host_label(&name)),
            port,
            address: host,
            txt: Vec::new(),
        };
        let mdns = args.auth.look.mdns.filter(|a| a.ip().is_multicast()).unwrap_or(st2110_discover::MDNS);
        let registrar = Registrar { shared: shared.clone(), finder, options, said: String::new(), advert, mdns };
        let registering = Some(thread::spawn(move || registrar.run()));
        Ok(Self {
            shared,
            registering,
            #[cfg(test)]
            api,
        })
    }

    /// What the Receiver's stream did lately, for its monitor.
    pub(crate) fn observe(&self, observation: monitor::Observation) {
        self.shared.lock().ncp.monitor.observe(observation, Instant::now());
    }

    /// Where the Sender's monitor reads its counts, every half second.
    pub(crate) fn watch(&self, watch: Watch) {
        self.shared.lock().watch = Some(watch);
    }

    /// Stops registering, and deletes the resources from the registry. Gives the
    /// registry's Registration API, when the Node was registered with one.
    pub(crate) fn finish(&mut self) -> Option<String> {
        self.shared.lock().stopping = true;
        self.shared.wake.notify_all();
        self.registering.take()?.join().ok().flatten()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Carries out scheduled activations when they are due, whether or not anything asks,
/// and has the monitor measure and report every half second.
fn tick(shared: &Shared) {
    let mut measured = Instant::now();
    loop {
        thread::sleep(TICK);
        {
            let mut state = shared.lock();
            if state.stopping {
                return;
            }
            connection::settle(&mut *state);
            if state.changed {
                shared.wake.notify_all();
            }
            let now = Instant::now();
            if now.duration_since(measured) >= MONITOR_TICK {
                measured = now;
                let up = st2110_discover::interfaces();
                let down: Vec<String> = state
                    .addresses
                    .iter()
                    .filter(|a| !a.is_loopback() && !up.iter().any(|i| i.address == **a))
                    .map(ToString::to_string)
                    .collect();
                let of = state.addresses.len();
                state.ncp.monitor.measure_link(monitor::Measured::link(&down, of));
                if let Some(observation) = state.watch.as_mut().map(|watch| watch()) {
                    state.ncp.monitor.observe(observation, now);
                }
                state.ncp.monitor.update(now);
            }
        }
        shared.notify();
    }
}

fn handle(shared: &Shared, stream: &TcpStream) {
    let Ok(Some(request)) = http::read(stream) else {
        return;
    };
    if under(request.path.trim_end_matches('/'), ncp::PATH).is_some() {
        if request.method == "GET" && http::is_upgrade(&request) {
            ncp::serve(shared, stream, &request);
            return;
        }
        let message = "the IS-12 control endpoint is a WebSocket: ask with GET and Upgrade: websocket";
        let mut response = Response::json(426, &error(426, "Upgrade Required", message).1);
        response.headers.push(("Upgrade", "websocket".into()));
        let _ = http::write(stream, &response);
        return;
    }
    let mut response = answer(shared, &request);
    // Any web page may read and control a Node, as IS-04 and IS-05 ask (APIs: Cross-Origin
    // Resource Sharing).
    response.headers.push(("Access-Control-Allow-Origin", "*".into()));
    let _ = http::write(stream, &response);
    shared.wake.notify_all();
}

fn answer(shared: &Shared, request: &Request) -> Response {
    if request.method == "OPTIONS" {
        let mut response = Response { status: 200, content_type: "text/plain", headers: Vec::new(), body: Vec::new() };
        response.headers.push(("Access-Control-Allow-Methods", "GET, PUT, POST, PATCH, HEAD, OPTIONS, DELETE".into()));
        response.headers.push(("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization".into()));
        response.headers.push(("Access-Control-Max-Age", "3600".into()));
        return response;
    }
    let body: Value = if request.body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(e) => return Response::json(400, &error(400, "Bad Request", &e.to_string()).1),
        }
    };
    let method = request.method.as_str();
    let path = request.path.trim_end_matches('/');
    if let Some(id) = under(path, "/x-nmos/node/v1.3/receivers")
        .and_then(|rest| rest.strip_suffix("/target"))
        .map(|id| id.trim_matches('/'))
        .filter(|id| !id.is_empty() && !id.contains('/'))
    {
        let (status, body) = target(shared, method, id, &body);
        return Response::json(status, &body);
    }
    let mut state = shared.lock();
    let read = |list: Value| if method == "GET" { (200, list) } else { error(405, "Method Not Allowed", "") };
    let (status, body) = match path {
        "" => read(json!(["x-nmos/"])),
        "/x-nmos" => read(json!(["node/", "connection/", "ncp/"])),
        "/x-nmos/ncp" => read(json!(["v1.0/"])),
        "/x-nmos/node" => read(json!(["v1.3/"])),
        "/x-nmos/connection" => read(json!([format!("{CONNECTION_VERSION}/")])),
        _ => match (under(path, "/x-nmos/node/v1.3"), under(path, &format!("/x-nmos/connection/{CONNECTION_VERSION}")))
        {
            (Some(rest), _) => node_api(&state, method, rest),
            (_, Some(rest)) => return connection::route(&mut *state, method, rest, &body),
            _ => error(404, "Not Found", "this Node serves IS-04 v1.3 and IS-05 v1.2"),
        },
    };
    Response::json(status, &body)
}

/// The rest of `path` after `prefix`, when it is under it.
fn under<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The Node API (IS-04 v1.3 APIs: Node API).
fn node_api(state: &State, method: &str, rest: &str) -> (u16, Value) {
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if method != "GET" {
        return error(405, "Method Not Allowed", "the Node API only reads");
    }
    let of = |kind: Kind| state.resources.iter().filter(move |(k, _)| *k == kind).map(|(_, r)| r);
    let kind = |name: &str| Kind::ALL.into_iter().find(|k| k.plural() == name && *k != Kind::Node);
    match parts.as_slice() {
        [] => (200, json!(["self/", "sources/", "flows/", "devices/", "senders/", "receivers/"])),
        ["self"] => (200, of(Kind::Node).next().cloned().unwrap_or(Value::Null)),
        [name] => match kind(name) {
            Some(kind) => (200, Value::Array(of(kind).cloned().collect())),
            None => error(404, "Not Found", "no such resource type"),
        },
        [name, id] => match kind(name).and_then(|kind| of(kind).find(|r| r["id"] == *id)) {
            Some(resource) => (200, resource.clone()),
            None => error(404, "Not Found", "no such resource"),
        },
        _ => error(404, "Not Found", "no such resource"),
    }
}

/// IS-04's `/target` (IS-04 v1.3 APIs: Node API, which deprecates it in favour of
/// IS-05): given a Sender, the Receiver takes its stream, as an IS-05 immediate
/// activation of the Sender's transport file, from its `manifest_href`, would have it,
/// and given `{}` it takes none. The Sender comes back with 202 (Accepted).
fn target(shared: &Shared, method: &str, id: &str, body: &Value) -> (u16, Value) {
    if method != "POST" {
        return error(405, "Method Not Allowed", "a Receiver's target is POSTed");
    }
    let constraints = {
        let mut state = shared.lock();
        let side = state.side;
        match state.endpoints(Side::Receiver).get(id) {
            Some(endpoint) if side == Side::Receiver => endpoint.constraints.clone(),
            _ => return error(404, "Not Found", "no such Receiver"),
        }
    };
    let Some(sender) = body.as_object() else {
        return error(400, "Bad Request", "the target is a Sender, or {} to take none");
    };
    let request = if sender.is_empty() {
        json!({"sender_id": null, "master_enable": false, "activation": Activation::Immediate.to_json()})
    } else {
        let Some(sender_id) = sender.get("id").and_then(Value::as_str) else {
            return error(400, "Bad Request", "the Sender has no id");
        };
        let Some(href) = sender.get("manifest_href").and_then(Value::as_str) else {
            return error(400, "Bad Request", "the Sender has no manifest_href to read its SDP file from");
        };
        // Fetched without holding the Node, which goes on answering meanwhile.
        let client = ConnectionClient::new(&st2110_connect::client::Options {
            timeout: TIMEOUT,
            ..st2110_connect::client::Options::default()
        });
        let sdp = match client.transport_file(href) {
            Ok(reply) if reply.is_success() => reply.body.as_str().unwrap_or_default().to_string(),
            Ok(reply) => return error(500, "Internal Server Error", &format!("{href}: {}", reply.error())),
            Err(e) => return error(500, "Internal Server Error", &e.to_string()),
        };
        let plan = Constraints::from_json(&constraints)
            .and_then(|constraints| Plan::connect(&sdp, Some(sender_id), &constraints, Activation::Immediate));
        match plan {
            Ok(plan) if plan.problems.is_empty() => plan.request,
            Ok(plan) => return error(400, "Bad Request", &plan.problems.join("; ")),
            Err(e) => return error(400, "Bad Request", &format!("the Sender's SDP file at {href}: {e}")),
        }
    };
    let (status, response) = connection::stage(&mut *shared.lock(), Side::Receiver, id, &request);
    if status >= 300 {
        return (status, response);
    }
    (202, body.clone())
}

/// Where the registry is: named, or to be found by DNS-SD.
enum Finder {
    Given(String),
    Look(LookArgs),
}

/// Registers the Node and keeps it registered.
struct Registrar {
    shared: Arc<Shared>,
    finder: Finder,
    options: Options,
    /// What it said last, so that it says each thing once.
    said: String,
    /// How it advertises the Node peer to peer, and where.
    advert: Instance,
    mdns: SocketAddrV4,
}

/// A registry registered with, and how it was found.
struct Registered {
    client: RegistrationClient,
    how: String,
}

impl Registrar {
    fn say(&mut self, message: String) {
        if message != self.said {
            eprintln!("{message}");
            self.said = message;
        }
    }

    /// Registers and heartbeats until told to stop, then deletes what it registered.
    fn run(mut self) -> Option<String> {
        let mut registry: Option<Registered> = None;
        let mut due = Instant::now();
        loop {
            let (stopping, changed) = {
                let mut state = self.shared.lock();
                loop {
                    if state.stopping || (state.changed && registry.is_some()) {
                        break;
                    }
                    let now = Instant::now();
                    if now >= due {
                        break;
                    }
                    state = self.shared.wake.wait_timeout(state, due - now).map_or_else(|e| e.into_inner().0, |r| r.0);
                }
                let changed = registry.is_some() && std::mem::take(&mut state.changed);
                (state.stopping, changed)
            };
            if stopping {
                self.unadvertise();
                let registered = registry?;
                self.withdraw(&registered.client);
                return Some(registered.client.base().to_string());
            }
            let Some(registered) = &registry else {
                match self.register() {
                    Ok(found) => {
                        self.say(format!("NMOS: registered with {} ({})", found.client.base(), found.how));
                        registry = Some(found);
                        due = Instant::now() + HEARTBEAT;
                        self.unadvertise();
                    }
                    Err((message, wait)) => {
                        self.say(message);
                        due = Instant::now() + wait;
                        self.advertise();
                    }
                }
                continue;
            };
            let lost = if changed {
                let endpoint = self.shared.lock().resources.last().cloned();
                match endpoint.map(|(kind, resource)| registered.client.register(kind, &resource)) {
                    Some(Ok(reply)) if matches!(reply.status, 200 | 201) => None,
                    Some(Ok(reply)) if reply.status == 404 => self.again(&registered.client),
                    Some(Ok(reply)) => Some(reply.error()),
                    Some(Err(e)) => Some(e.to_string()),
                    None => None,
                }
            } else if Instant::now() >= due {
                due += HEARTBEAT;
                let node = self.shared.lock().resources[0].1["id"].as_str().unwrap_or_default().to_string();
                match registered.client.heartbeat(&node) {
                    Ok(reply) if reply.status == 200 => None,
                    // Forgotten, as after the registry's restart: register everything again.
                    Ok(reply) if reply.status == 404 => {
                        self.say(format!("NMOS: {} forgot this Node, so it registers again", registered.client.base()));
                        self.again(&registered.client)
                    }
                    Ok(reply) => Some(reply.error()),
                    Err(e) => Some(e.to_string()),
                }
            } else {
                None
            };
            if let Some(why) = lost {
                let base = registry.take().map(|r| r.client.base().to_string()).unwrap_or_default();
                self.say(format!("NMOS: lost the registry at {base} ({why}); looking for one again"));
                due = Instant::now();
            }
        }
    }

    /// Advertises the Node peer to peer, unless it already is (IS-04 v1.3 Discovery:
    /// Peer to Peer, for a Node that finds no registry).
    fn advertise(&mut self) {
        let shared = self.shared.clone();
        // Held until the responder is in place, so that no change to the counters is missed.
        let mut state = shared.lock();
        if state.advertising.is_some() {
            return;
        }
        let advert = Instance { txt: state.txt(), ..self.advert.clone() };
        let name = advert.full_name();
        match Responder::start(advert, self.mdns) {
            Ok(responder) => {
                state.advertising = Some(responder);
                drop(state);
                eprintln!(
                    "NMOS: with no registry, the Node advertises itself peer to peer by multicast DNS, as {name}"
                );
            }
            Err(e) => {
                drop(state);
                self.say(format!("NMOS: cannot advertise the Node by multicast DNS: {e}"));
            }
        }
    }

    /// Stops advertising the Node peer to peer, saying goodbye.
    fn unadvertise(&self) {
        let responder = self.shared.lock().advertising.take();
        if let Some(responder) = responder {
            responder.stop();
        }
    }

    /// Registers everything again with a registry that has forgotten the Node: `Some`
    /// with what went wrong when it cannot.
    fn again(&self, client: &RegistrationClient) -> Option<String> {
        self.register_all(client).err()
    }

    /// Finds a registry and registers everything with it, or says what went wrong and
    /// how long to wait before trying again.
    fn register(&self) -> Result<Registered, (String, Duration)> {
        let candidates: Vec<(String, String)> = match &self.finder {
            Finder::Given(url) => vec![(url.clone(), "given".into())],
            Finder::Look(look) => match find::registration_apis(look, TIMEOUT, self.options.token.is_some()) {
                Ok(apis) => apis.into_iter().map(|a| (a.url, format!("{}, found by {}", a.name, a.by))).collect(),
                Err(e) => {
                    return Err((
                        format!(
                            "NMOS: {e}; the Node API serves the resources peer to peer, and DNS-SD is asked again \
                             every {} s",
                            LOOK_AGAIN.as_secs()
                        ),
                        LOOK_AGAIN,
                    ));
                }
            },
        };
        let mut problems = Vec::new();
        for (url, how) in candidates {
            match RegistrationClient::connect(&url, &self.options) {
                Ok(client) => match self.register_all(&client) {
                    Ok(()) => return Ok(Registered { client, how }),
                    Err(e) => problems.push(e),
                },
                Err(e) => problems.push(e.to_string()),
            }
        }
        Err((format!("NMOS: cannot register: {}; trying again", problems.join("; ")), RETRY))
    }

    /// Registers every resource, the Node first.
    fn register_all(&self, client: &RegistrationClient) -> Result<(), String> {
        let resources = self.shared.lock().resources.clone();
        for (kind, resource) in resources {
            let reply = client.register(kind, &resource).map_err(|e| e.to_string())?;
            if !matches!(reply.status, 200 | 201) {
                return Err(format!("{} {}: {}", client.base(), kind.as_str(), reply.error()));
            }
        }
        Ok(())
    }

    /// Deletes every resource, the Node last.
    fn withdraw(&self, client: &RegistrationClient) {
        let resources = self.shared.lock().resources.clone();
        for (kind, resource) in resources.iter().rev() {
            let _ = client.delete(*kind, resource["id"].as_str().unwrap_or_default());
        }
    }
}

/// Whether a Node API answers at `api`: for tests.
#[cfg(test)]
fn get(api: &str) -> std::io::Result<String> {
    send("GET", api, None)
}

/// A request to a Node's APIs, and the whole response: for tests.
#[cfg(test)]
fn send(method: &str, url: &str, body: Option<&Value>) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut stream = TcpStream::connect(host)?;
    let body = body.map(Value::to_string).unwrap_or_default();
    write!(stream, "{method} /{path} HTTP/1.1\r\nHost: {host}\r\n")?;
    if !body.is_empty() {
        write!(stream, "Content-Type: application/json\r\nContent-Length: {}\r\n", body.len())?;
    }
    write!(stream, "\r\n{body}")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use st2110_media::describe::Leg;
    use st2110_media::describe::Media;
    use st2110_media::format::AudioFormat;

    #[test]
    fn serves_the_node_api_and_the_connection_api() {
        let description = Description {
            name: "test tone".into(),
            media: Media::Audio(AudioFormat::new(2)),
            payload_type: 97,
            legs: vec![Leg { destination: "239.1.2.3:5004".parse().unwrap(), source: Some(Ipv4Addr::LOCALHOST) }],
            clock: Clock::parse("traceable").ok(),
            ttl: 1,
            rtp_offset: 0,
        };
        let constraints =
            vec![json!({"source_ip": {"enum": ["auto", "127.0.0.1"]}, "destination_ip": {}, "source_port": {},
                                      "destination_port": {}, "rtp_enabled": {}})];
        let params = vec![json!({"source_ip": "127.0.0.1", "destination_ip": "239.1.2.3", "source_port": 0,
                                 "destination_port": 5004, "rtp_enabled": true})];
        struct Quiet;
        impl Role for Quiet {
            fn side(&self) -> Side {
                Side::Sender
            }
            fn check(&self, _: &Value) -> Result<(), String> {
                Ok(())
            }
            fn activate(&mut self, _: &mut Value) {}
            fn transport_file(&self) -> Option<String> {
                Some("v=0\r\n".into())
            }
        }
        // A registry no one answers at, so that nothing is registered.
        let mut args = NodeArgs { nmos: Some("http://127.0.0.1:9".into()), ..NodeArgs::default() };
        args.auth.look.mdns = Some(test_group());
        let mut node = Node::start(
            &args,
            &Offer::Sender(&description),
            &[Ipv4Addr::LOCALHOST],
            Endpoint::sender(constraints, params, true),
            Box::new(Quiet),
            37,
        )
        .unwrap();
        let senders = get(&format!("{}senders/", node.api)).unwrap();
        assert!(senders.starts_with("HTTP/1.1 200"), "{senders}");
        assert!(senders.contains("\"label\":\"test tone\""), "{senders}");
        assert!(senders.contains("Access-Control-Allow-Origin: *"), "{senders}");
        let base = node.api.replace("node/v1.3", "connection/v1.2");
        let file = get(&format!("{base}single/senders/")).unwrap();
        let id = file.split('"').nth(1).unwrap().trim_end_matches('/').to_string();
        let sdp = get(&format!("{base}single/senders/{id}/transportfile")).unwrap();
        assert!(sdp.contains("application/sdp") && sdp.ends_with("v=0\r\n"), "{sdp}");
        let kind = get(&format!("{base}single/senders/{id}/transporttype")).unwrap();
        assert!(kind.ends_with("\"urn:x-nmos:transport:rtp.mcast\""), "{kind}");

        // The IS-12 endpoint the Device lists: a WebSocket, with the Sender's monitor.
        let device = get(&format!("{}devices/", node.api)).unwrap();
        let href = device.split('"').find(|s| s.starts_with("ws://")).expect("an IS-12 control").to_string();
        assert!(href.ends_with("/x-nmos/ncp/v1.0/"), "{href}");
        let plain = get(&href.replace("ws://", "http://")).unwrap();
        assert!(plain.starts_with("HTTP/1.1 426"), "{plain}");
        let mut ncp = st2110_nmos::ncp::client::Connection::open(&href, &[], TIMEOUT).unwrap();
        let monitors = ncp.monitors().unwrap();
        assert_eq!(monitors.len(), 1, "{monitors:?}");
        let read = ncp.read_monitor(&monitors[0]).unwrap();
        assert_eq!(read["role"], "sender-monitor", "{read}");
        assert_eq!(read["touchpoints"][0]["resource"]["id"], id.as_str(), "{read}");
        assert_eq!(ncp.subscribe(&[4, 99]).unwrap(), [4]);
        let delay = st2110_nmos::ncp::property::STATUS_REPORTING_DELAY;
        ncp.call(4, st2110_nmos::ncp::method::SET, json!({"id": delay.json(), "value": 0})).unwrap();
        let heard = std::iter::from_fn(|| ncp.next_change().ok().flatten()).find(|n| n.property == delay).unwrap();
        assert_eq!((heard.oid, heard.value), (4, json!(0)));
        ncp.close();
        assert_eq!(node.finish(), None, "never registered");
    }

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.168.10.21\r\ns=CAM 1\r\nt=0 0\r\n\
        m=audio 5004 RTP/AVP 97\r\nc=IN IP4 239.1.1.1/32\r\na=source-filter: incl IN IP4 239.1.1.1 192.168.10.21\r\n\
        a=rtpmap:97 L24/48000/2\r\na=ptime:1\r\na=ts-refclk:localmac=02-00-00-00-00-01\r\na=mediaclk:direct=0\r\n";

    /// Serves `SDP` at every path, as a Sender's `manifest_href`; gives the port.
    fn serve_sdp() -> u16 {
        use std::io::{Read, Write};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    SDP.len()
                );
                let _ = stream.write_all(format!("{head}{SDP}").as_bytes());
            }
        });
        port
    }

    /// Whether multicast sent over loopback comes back to this machine; some sandboxes
    /// do not deliver it.
    fn multicast_loops(group: SocketAddrV4) -> bool {
        let heard = || -> std::io::Result<bool> {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, group.port()))?;
            socket.join_multicast_v4(group.ip(), &Ipv4Addr::LOCALHOST)?;
            socket.set_multicast_loop_v4(true)?;
            socket.set_read_timeout(Some(Duration::from_millis(500)))?;
            // Sent from a loopback address, it goes out on loopback.
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            sender.set_multicast_loop_v4(true)?;
            sender.send_to(b"loop", group)?;
            let mut buffer = [0u8; 16];
            Ok(socket.recv_from(&mut buffer).is_ok_and(|(n, _)| &buffer[..n] == b"loop"))
        };
        heard().unwrap_or(false)
    }

    /// A Receiver's Node, as `st2110 receive --nmos` starts one on loopback, and what
    /// it is told to receive.
    fn receiver_node(args: &NodeArgs) -> (Node, Arc<Tuning>) {
        let addresses = [Ipv4Addr::LOCALHOST; 2];
        let constraints = addresses
            .iter()
            .map(|a| {
                json!({"source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["auto", a.to_string()]},
                       "destination_port": {"minimum": 1, "maximum": 65535}, "rtp_enabled": {}})
            })
            .collect();
        let named: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        let tuning = Arc::new(Tuning::default());
        let node = Node::start(
            args,
            &Offer::Receiver { video: false, legs: 2 },
            &addresses,
            Endpoint::idle_receiver(&named, constraints),
            Box::new(Receiving::new(tuning.clone(), true)),
            37,
        )
        .unwrap();
        (node, tuning)
    }

    /// A multicast DNS group of the test's own, on a free port, for the Node to
    /// advertise itself at rather than the network's.
    fn test_group() -> SocketAddrV4 {
        let port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port();
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), port)
    }

    #[test]
    fn a_target_connects_the_receiver_as_is05_would() {
        let mut args = NodeArgs { nmos: Some("http://127.0.0.1:9".into()), ..NodeArgs::default() };
        args.auth.look.mdns = Some(test_group());
        let (mut node, tuning) = receiver_node(&args);
        let receivers = get(&format!("{}receivers/", node.api)).unwrap();
        let id = receivers.split("\"id\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        let target = format!("{}receivers/{id}/target", node.api);
        let sender = json!({"id": "5e0d0001-0000-4000-8000-000000000001", "label": "CAM 1",
                            "manifest_href": format!("http://127.0.0.1:{}/sdp", serve_sdp())});
        let response = send("POST", &target, Some(&sender)).unwrap();
        assert!(response.starts_with("HTTP/1.1 202"), "{response}");
        assert!(response.contains("\"label\":\"CAM 1\""), "the Sender comes back: {response}");
        let tuned = tuning.take().expect("a stream to receive");
        assert_eq!(tuned.sender_id.as_deref(), Some("5e0d0001-0000-4000-8000-000000000001"));
        assert_eq!(tuned.description.legs.len(), 1, "the second leg is off");
        assert_eq!(tuned.description.legs[0].destination.to_string(), "239.1.1.1:5004");
        let resource = get(&format!("{}receivers/{id}", node.api)).unwrap();
        assert!(resource.contains("\"subscription\":{\"active\":true,\"sender_id\":\"5e0d0001"), "{resource}");
        let active = node.api.replace("node/v1.3", "connection/v1.2") + &format!("single/receivers/{id}/active");
        let active = get(&active).unwrap();
        assert!(active.contains("\"master_enable\":true") && active.contains("239.1.1.1"), "{active}");

        // `{}` takes none.
        let response = send("POST", &target, Some(&json!({}))).unwrap();
        assert!(response.starts_with("HTTP/1.1 202") && response.ends_with("{}"), "{response}");
        assert!(tuning.take().is_none());
        let resource = get(&format!("{}receivers/{id}", node.api)).unwrap();
        assert!(resource.contains("\"subscription\":{\"active\":false,\"sender_id\":null"), "{resource}");

        // Asked wrongly.
        let status = |response: std::io::Result<String>| response.unwrap()[9..12].to_string();
        assert_eq!(status(get(&target)), "405");
        assert_eq!(status(send("POST", &target.replace(&id, "nobody"), Some(&sender))), "404");
        assert_eq!(status(send("POST", &target, Some(&json!({"id": "x"})))), "400");
        let nowhere = json!({"id": "x", "manifest_href": "http://127.0.0.1:9/sdp"});
        assert_eq!(status(send("POST", &target, Some(&nowhere))), "500");
        assert_eq!(node.finish(), None, "never registered");
    }

    #[test]
    fn advertises_itself_by_multicast_dns_when_there_is_no_registry() {
        use st2110_discover::find::{Look, find};
        use st2110_discover::nmos::ApiKind;
        let group = test_group();
        if !multicast_loops(group) {
            eprintln!("skipped: multicast sent over loopback does not come back on this machine");
            return;
        }
        // No registry to be found: a DNS server that is not there, and nothing
        // advertised in the test's group.
        let mut args =
            NodeArgs { nmos: Some(String::new()), label: Some("Test monitor".into()), ..NodeArgs::default() };
        args.auth.look.mdns = Some(group);
        args.auth.look.dns_server = vec!["127.0.0.1:9".parse().unwrap()];
        args.auth.look.domain = vec!["nowhere.test".into()];
        let (mut node, _tuning) = receiver_node(&args);
        let look = Look { dns: false, mdns: Some(group), listen: Duration::from_secs(15), ..Look::default() };
        let found = |ver_rcv: &str| {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let seen = find(ApiKind::Node, &look);
                if let [api] = &seen.apis[..]
                    && api.counters.get("ver_rcv").is_some_and(|v| v == ver_rcv)
                {
                    return api.clone();
                }
                assert!(Instant::now() < deadline, "not found with ver_rcv {ver_rcv}: {seen:?}");
            }
        };
        let api = found("0");
        assert_eq!(format!("{}/x-nmos/node/v1.3/", api.url), node.api);
        assert_eq!((api.name.as_str(), api.versions.clone(), api.auth), ("Test monitor", vec!["v1.3".into()], false));
        assert_eq!(api.counters.len(), 6, "{:?}", api.counters);

        // A change to the Receiver goes up its counter, and is announced.
        let receivers = get(&format!("{}receivers/", node.api)).unwrap();
        let id = receivers.split("\"id\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        let response = send("POST", &format!("{}receivers/{id}/target", node.api), Some(&json!({}))).unwrap();
        assert!(response.starts_with("HTTP/1.1 202"), "{response}");
        assert_eq!(found("1").counters["ver_slf"], "0");
        assert_eq!(node.finish(), None, "never registered");
    }
}
