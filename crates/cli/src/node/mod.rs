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
//! Where DNS-SD finds no registry, the Node API still serves the resources, for a
//! controller that is told where it is, and DNS-SD is asked again every 30 seconds.
//! The Node does not advertise itself by multicast DNS for peer-to-peer discovery.
//!
//! An activation through IS-05 changes the running stream: a Sender sends to the new
//! destination, or stops and starts with `master_enable` ([`sending`]), and a Receiver
//! receives what the transport file and parameters describe ([`receiving`]). The
//! registry hears of each, as IS-04 asks.

pub(crate) mod connection;
mod receiving;
mod resources;
mod sending;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
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
    /// one DNS-SD finds when no URL is given. A controller can then move the stream, or
    /// turn it off and on.
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
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

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
}

impl State {
    fn endpoint_resource(&mut self) -> &mut Value {
        &mut self.resources.last_mut().expect("a Sender or Receiver").1
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
        let resource = self.endpoint_resource();
        resource["subscription"] = subscription;
        resource["version"] = json!(tai(at));
        self.changed = true;
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
        let state = State {
            resources,
            side,
            endpoints: BTreeMap::from([(ids.endpoint.clone(), endpoint)]),
            none: BTreeMap::new(),
            role,
            tai_utc,
            changed: false,
            stopping: false,
        };
        let shared = Arc::new(Shared { state: Mutex::new(state), wake: Condvar::new() });
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
            "NMOS: {} {} at {api}, its Connection API at http://{host}:{port}/x-nmos/connection/{CONNECTION_VERSION}/",
            side.name(),
            ids.endpoint
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
        let registrar = Registrar { shared: shared.clone(), finder, options, said: String::new() };
        let registering = Some(thread::spawn(move || registrar.run()));
        Ok(Self {
            shared,
            registering,
            #[cfg(test)]
            api,
        })
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

/// Carries out scheduled activations when they are due, whether or not anything asks.
fn tick(shared: &Shared) {
    loop {
        thread::sleep(TICK);
        let mut state = shared.lock();
        if state.stopping {
            return;
        }
        connection::settle(&mut *state);
        if state.changed {
            shared.wake.notify_all();
        }
    }
}

fn handle(shared: &Shared, stream: &TcpStream) {
    let Ok(Some(request)) = http::read(stream) else {
        return;
    };
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
    let mut state = shared.lock();
    let read = |list: Value| if method == "GET" { (200, list) } else { error(405, "Method Not Allowed", "") };
    let (status, body) = match path {
        "" => read(json!(["x-nmos/"])),
        "/x-nmos" => read(json!(["node/", "connection/"])),
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
    if let ["receivers", _, "target"] = parts.as_slice() {
        return error(501, "Not Implemented", "connect this Receiver through its IS-05 Connection API");
    }
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
                    }
                    Err((message, wait)) => {
                        self.say(message);
                        due = Instant::now() + wait;
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
    use std::io::{Read, Write};
    let rest = api.strip_prefix("http://").unwrap_or(api);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut stream = TcpStream::connect(host)?;
    write!(stream, "GET /{path} HTTP/1.1\r\nHost: {host}\r\n\r\n")?;
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
        let args = NodeArgs { nmos: Some("http://127.0.0.1:9".into()), ..NodeArgs::default() };
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
        assert_eq!(node.finish(), None, "never registered");
    }
}
