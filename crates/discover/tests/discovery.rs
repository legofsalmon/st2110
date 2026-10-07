//! Discovery on this machine alone: SAP over loopback, a Node found by asking a stand-in
//! multicast DNS responder, and a registry found by asking a stand-in DNS server, both
//! serving the test facility over HTTP.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_discover::dns::{self, Data, Message, Name, Record};
use st2110_discover::{Announcer, Discovery, List, Options, Origin, nmos::ApiKind};

const FACILITY: &str = include_str!("../../nmos/tests/fixtures/facility.json");
const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";

fn facility() -> Value {
    serde_json::from_str(FACILITY).unwrap()
}

fn video_sdp() -> String {
    facility()["manifests"][VIDEO_SENDER]["sdp"].as_str().unwrap().to_string()
}

/// Options that look nowhere, for each test to add where to look.
fn nowhere() -> Options {
    Options {
        interfaces: vec![Ipv4Addr::LOCALHOST],
        sap: vec![],
        nmos: false,
        mdns: None,
        dns: false,
        refresh: Duration::from_secs(1),
        timeout: Duration::from_secs(5),
        ..Options::default()
    }
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Starts looking, and a channel that hears each time the list changes.
fn start(options: Options) -> (Discovery, mpsc::Receiver<()>) {
    let (changed, heard) = mpsc::channel();
    let discovery = Discovery::start(options, move || _ = changed.send(()));
    (discovery, heard)
}

/// Waits up to 15 s for the list to be as `ready` says, calling `meanwhile` as it waits.
fn wait_for(discovery: &Discovery, changed: &mpsc::Receiver<()>, ready: impl Fn(&List) -> bool) -> List {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let list = discovery.list();
        if ready(&list) {
            return list;
        }
        assert!(Instant::now() < deadline, "gave up waiting; the list is {list:#?}");
        let _ = changed.recv_timeout(Duration::from_millis(100));
    }
}

/// A response: status and body.
type Reply = (u16, String);

/// An HTTP server on a free port that answers each request target with `route`, which
/// is also given the port.
fn serve(route: impl Fn(u16, &str) -> Reply + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let port = listener.local_addr().unwrap().port();
    let route = Arc::new(route);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let route = route.clone();
            std::thread::spawn(move || handle(stream, port, &*route));
        }
    });
    port
}

fn handle(mut stream: TcpStream, port: u16, route: &dyn Fn(u16, &str) -> Reply) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).map_or(true, |n| n == 0) || header == "\r\n" {
            break;
        }
    }
    let target = request.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = route(port, target);
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = stream.write_all(response.as_bytes());
}

/// The SDP files of the test facility, as its Senders' `manifest_href`s and the
/// Connection API's `/transportfile` serve them.
fn sdp_file(facility: &Value, target: &str) -> Option<Reply> {
    let transport_file = target
        .strip_prefix("/x-nmos/connection/v1.1/single/senders/")
        .and_then(|rest| rest.strip_suffix("/transportfile"));
    let id = target.strip_prefix("/sdp/").or(transport_file)?;
    Some(match facility["manifests"][id]["sdp"].as_str() {
        Some(sdp) => (200, sdp.to_string()),
        None => (404, String::new()),
    })
}

/// The facility with its SDP files and Connection APIs at this server.
fn served_facility(port: u16) -> Value {
    let mut facility = facility();
    for sender in facility["senders"].as_array_mut().unwrap() {
        let id = sender["id"].as_str().unwrap().to_string();
        sender["manifest_href"] = json!(format!("http://127.0.0.1:{port}/sdp/{id}"));
    }
    for device in facility["devices"].as_array_mut().unwrap() {
        device["controls"][0]["href"] = json!(format!("http://127.0.0.1:{port}/x-nmos/connection/v1.1/"));
    }
    facility
}

/// The test facility's Camera 1 as its Node API serves it.
fn camera_node(port: u16, target: &str) -> Reply {
    let facility = served_facility(port);
    if let Some(reply) = sdp_file(&facility, target) {
        return reply;
    }
    let node = facility["nodes"][0].clone();
    let mine = |collection: &str, key: &str, id: &Value| -> Value {
        let items = facility[collection].as_array().unwrap();
        Value::Array(items.iter().filter(|item| &item[key] == id).cloned().collect())
    };
    let devices = mine("devices", "node_id", &node["id"]);
    let device = devices[0]["id"].clone();
    let body = match target {
        "/x-nmos/node/" => json!(["v1.2/", "v1.3/"]),
        "/x-nmos/node/v1.3/self/" => node,
        "/x-nmos/node/v1.3/devices/" => devices,
        "/x-nmos/node/v1.3/sources/" => mine("sources", "device_id", &device),
        "/x-nmos/node/v1.3/flows/" => mine("flows", "device_id", &device),
        "/x-nmos/node/v1.3/senders/" => mine("senders", "device_id", &device),
        "/x-nmos/node/v1.3/receivers/" => mine("receivers", "device_id", &device),
        _ => return (404, String::new()),
    };
    (200, body.to_string())
}

/// The test facility as a registry's Query API serves it, unpaged.
fn registry(port: u16, target: &str) -> Reply {
    let facility = served_facility(port);
    if let Some(reply) = sdp_file(&facility, target) {
        return reply;
    }
    if target == "/x-nmos/query/" {
        return (200, json!(["v1.3/"]).to_string());
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    match path.strip_prefix("/x-nmos/query/v1.3/").map(|c| c.trim_end_matches('/')) {
        Some(collection) if facility[collection].is_array() => (200, facility[collection].to_string()),
        _ => (404, String::new()),
    }
}

/// A DNS-SD service instance to advertise.
struct Advertised {
    service: Name,
    instance: Name,
    host: Name,
    port: u16,
    txt: Vec<&'static str>,
}

impl Advertised {
    fn new(instance: &str, service: &str, host: &str, port: u16, txt: Vec<&'static str>) -> Self {
        let service = Name::parse(service);
        Self { instance: service.child(instance), service, host: Name::parse(host), port, txt }
    }

    fn records(&self, ttl: u32) -> [Record; 4] {
        let txt = self.txt.iter().map(|s| s.as_bytes().to_vec()).collect();
        let srv = Data::Srv { priority: 0, weight: 0, port: self.port, target: self.host.clone() };
        [
            Record::new(self.service.clone(), ttl, Data::Ptr(self.instance.clone())),
            Record::new(self.instance.clone(), ttl, srv),
            Record::new(self.instance.clone(), ttl, Data::Txt(txt)),
            Record::new(self.host.clone(), ttl, Data::A(Ipv4Addr::LOCALHOST)),
        ]
    }
}

/// How a stand-in server answers.
#[derive(Clone, Copy, PartialEq)]
enum Answers {
    /// As a multicast DNS responder: all four records to a browse, live or saying goodbye.
    Mdns,
    /// As a DNS server: only the record asked for, and no such name otherwise.
    Dns,
}

/// A stand-in multicast DNS responder or DNS server on `socket`, answering for
/// `advertised` until `gone` is set, then saying goodbye.
fn answer(socket: UdpSocket, advertised: Advertised, answers: Answers, gone: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 9000];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buffer) else { continue };
            let Ok(query) = Message::decode(&buffer[..n]) else { continue };
            if query.response {
                continue;
            }
            let ttl = if gone.load(Ordering::Relaxed) { 0 } else { 10 };
            let [ptr, srv, txt, a] = advertised.records(ttl);
            let mut response = Message { id: query.id, response: true, authoritative: true, ..Message::default() };
            for question in &query.questions {
                let matching =
                    [&ptr, &srv, &txt, &a].into_iter().find(|r| r.name == question.name && r.kind == question.kind);
                match (answers, matching) {
                    (Answers::Mdns, Some(record)) if record.kind == dns::PTR => {
                        response.answers.push(ptr.clone());
                        response.additionals.extend([srv.clone(), txt.clone(), a.clone()]);
                    }
                    (_, Some(record)) => response.answers.push(record.clone()),
                    (Answers::Dns, None) => response.rcode = 3,
                    (Answers::Mdns, None) => {}
                }
            }
            if answers == Answers::Dns {
                response.questions.clone_from(&query.questions);
            }
            if !response.answers.is_empty() || response.rcode != 0 {
                let _ = socket.send_to(&response.encode(), from);
            }
        }
    });
}

#[test]
fn hears_sap_and_forgets_a_deleted_session() {
    let to = SocketAddrV4::new(Ipv4Addr::LOCALHOST, free_udp_port());
    let (discovery, changed) = start(Options { sap: vec![to], ..nowhere() });
    let looking = format!("SAP announcements to {to}");
    assert_eq!(discovery.list().looking, [looking]);
    let announcer = Announcer::new(&video_sdp(), to, Some(Ipv4Addr::LOCALHOST), 1).unwrap();
    announcer.announce().unwrap();
    let list = wait_for(&discovery, &changed, |l| !l.streams.is_empty());
    let [stream] = &list.streams[..] else { panic!("one stream, not {:#?}", list.streams) };
    assert_eq!(stream.name, "CAM 1 video");
    assert_eq!(stream.sdp.as_deref(), Some(video_sdp().as_str()));
    assert_eq!(stream.destinations(), ["239.10.10.1:5004", "239.20.10.1:5004"]);
    assert!(stream.format().starts_with("ST 2110-20, 1920x1080 progressive, 50 fps"), "{}", stream.format());
    assert!(!stream.stale && stream.problem.is_none() && stream.active.is_none());
    let [Origin::Sap { announcer: from, interval_s: None, .. }] = &stream.by[..] else { panic!("{:?}", stream.by) };
    assert_eq!(*from, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(list.notes.is_empty(), "{:?}", list.notes);
    // Deleted, it goes at once.
    announcer.delete().unwrap();
    wait_for(&discovery, &changed, |l| l.streams.is_empty());
    // Something that is not SAP is noted.
    UdpSocket::bind("127.0.0.1:0").unwrap().send_to(b"\x20\x00", to).unwrap();
    let list = wait_for(&discovery, &changed, |l| !l.notes.is_empty());
    assert_eq!(list.notes, ["1 SAP packet could not be read, the last because 2 octets is too short for a SAP header"]);
}

#[test]
fn finds_a_node_by_multicast_dns_and_reads_it_peer_to_peer() {
    let node = serve(camera_node);
    let txt = vec!["api_proto=http", "api_ver=v1.2,v1.3", "api_auth=false", "ver_slf=0", "ver_snd=0", "ver_flw=0"];
    let advertised = Advertised::new("Camera 1", "_nmos-node._tcp.local", "camera-1.local", node, txt);
    let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mdns = match responder.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let gone = Arc::new(AtomicBool::new(false));
    answer(responder, advertised, Answers::Mdns, gone.clone());
    let (discovery, changed) = start(Options { nmos: true, mdns: Some(mdns), ..nowhere() });
    let list = wait_for(&discovery, &changed, |l| l.streams.len() == 2 && !l.busy);
    assert_eq!(list.looking, ["NMOS registries and Nodes by multicast DNS, from a port of its own"]);
    let [api] = &list.apis[..] else { panic!("one API, not {:#?}", list.apis) };
    let url = format!("http://127.0.0.1:{node}");
    assert_eq!(
        (api.kind, api.name.as_str(), api.url.as_str(), api.by.as_str()),
        (ApiKind::Node, "Camera 1", url.as_str(), "mDNS")
    );
    assert_eq!(api.versions, ["v1.2", "v1.3"]);
    assert_eq!(api.counters.keys().collect::<Vec<_>>(), ["ver_flw", "ver_slf", "ver_snd"]);
    assert!(list.peer_to_peer && list.registry.is_none());
    let names: Vec<&str> = list.streams.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["CAM 1 audio", "CAM 1 video"]);
    let video = &list.streams[1];
    assert_eq!(video.sdp.as_deref(), Some(video_sdp().as_str()));
    assert_eq!(video.active, Some(true));
    let [Origin::Nmos { id, node: Some(node_label), api, peer_to_peer: true, .. }] = &video.by[..] else {
        panic!("{:?}", video.by)
    };
    assert_eq!((id.as_str(), node_label.as_str()), (VIDEO_SENDER, "Camera 1"));
    assert_eq!(*api, format!("{url}/x-nmos/node/v1.3/"));
    assert_eq!(video.by[0].describe(), "NMOS Node Camera 1");
    assert!(list.notes.is_empty(), "{:?}", list.notes);
    // The Node says goodbye, and its streams go with it.
    gone.store(true, Ordering::Relaxed);
    discovery.refresh();
    let list = wait_for(&discovery, &changed, |l| l.streams.is_empty() && !l.busy);
    assert!(list.apis.is_empty() && !list.peer_to_peer);
}

#[test]
fn finds_a_registry_by_unicast_dns_sd_and_merges_what_sap_announces() {
    let registry = serve(registry);
    let txt = vec!["api_proto=http", "api_ver=v1.3", "api_auth=false", "pri=10"];
    let advertised = Advertised::new("Registry", "_nmos-query._tcp.studio.test", "registry.studio.test", registry, txt);
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns_server = server.local_addr().unwrap();
    answer(server, advertised, Answers::Dns, Arc::new(AtomicBool::new(false)));
    let sap = SocketAddrV4::new(Ipv4Addr::LOCALHOST, free_udp_port());
    let options = Options {
        sap: vec![sap],
        nmos: true,
        dns: true,
        dns_servers: vec![dns_server],
        // Nothing is advertised in the second, which is no problem.
        domains: Some(vec!["studio.test".into(), "empty.test".into()]),
        ..nowhere()
    };
    let (discovery, changed) = start(options);
    Announcer::new(&video_sdp(), sap, Some(Ipv4Addr::LOCALHOST), 1).unwrap().announce().unwrap();
    let list = wait_for(&discovery, &changed, |l| l.streams.len() == 2 && l.streams[1].by.len() == 2 && !l.busy);
    assert_eq!(
        list.looking,
        [format!("SAP announcements to {sap}"), "NMOS registries by DNS-SD in studio.test, empty.test".to_string()]
    );
    let [api] = &list.apis[..] else { panic!("one API, not {:#?}", list.apis) };
    assert_eq!(
        (api.kind, api.name.as_str(), api.by.as_str(), api.priority),
        (ApiKind::Query, "Registry", "DNS in studio.test", Some(10))
    );
    let base = format!("http://127.0.0.1:{registry}/x-nmos/query/v1.3/");
    assert_eq!((list.registry.as_deref(), list.peer_to_peer), (Some(base.as_str()), false));
    let video = &list.streams[1];
    assert_eq!(video.name, "CAM 1 video");
    let described: Vec<String> = video.by.iter().map(Origin::describe).collect();
    assert_eq!(described, ["NMOS Node Camera 1", "SAP from 127.0.0.1"]);
    assert!(list.notes.is_empty(), "{:?}", list.notes);
}

/// A registry given by its URL is read without looking for one, and one that cannot be
/// read is noted.
#[test]
fn reads_a_registry_it_is_given_and_notes_one_it_cannot_read() {
    let registry = serve(registry);
    let given = format!("http://127.0.0.1:{registry}");
    let (discovery, changed) = start(Options { nmos: true, registry: Some(given.clone()), ..nowhere() });
    let list = wait_for(&discovery, &changed, |l| l.streams.len() == 2 && !l.busy);
    assert_eq!(list.looking, [format!("the NMOS registry at {given}")]);
    assert_eq!(list.registry, Some(format!("{given}/x-nmos/query/v1.3/")));
    drop(discovery);
    let nothing = format!("http://127.0.0.1:{}", free_udp_port());
    let (discovery, changed) = start(Options { nmos: true, registry: Some(nothing.clone()), ..nowhere() });
    let list = wait_for(&discovery, &changed, |l| !l.notes.is_empty() && !l.busy);
    assert!(list.streams.is_empty());
    assert!(list.looking.is_empty(), "a registry that has not answered is nowhere it looks: {:?}", list.looking);
    let [note] = &list.notes[..] else { panic!("{:?}", list.notes) };
    assert!(note.starts_with(&format!("Cannot read the NMOS registry at {nothing}: ")), "{note}");
}

/// Multicast over loopback, as Linux delivers it: SAP to a group, and a multicast DNS
/// responder that answers to the group.
#[cfg(target_os = "linux")]
#[test]
fn hears_multicast_over_loopback() {
    use socket2::{Domain, Protocol, Socket, Type};
    let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 255), free_udp_port());
    let mdns = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), free_udp_port());
    // The responder shares the group's port with the querier, as the system's does.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, mdns.port()).into()).unwrap();
    socket.join_multicast_v4(mdns.ip(), &Ipv4Addr::LOCALHOST).unwrap();
    socket.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).unwrap();
    socket.set_multicast_loop_v4(true).unwrap();
    let responder: UdpSocket = socket.into();
    let node = serve(camera_node);
    let advertised = Advertised::new("Camera 1", "_nmos-node._tcp.local", "camera-1.local", node, vec!["api_ver=v1.3"]);
    // Answers go to the group, where the querier hears them.
    let to_group = responder.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 9000];
        loop {
            let Ok((n, _)) = to_group.recv_from(&mut buffer) else { continue };
            match Message::decode(&buffer[..n]) {
                Ok(query) if !query.response && query.questions.iter().any(|q| q.kind == dns::PTR) => {
                    let [ptr, srv, txt, a] = advertised.records(120);
                    let response = Message {
                        response: true,
                        authoritative: true,
                        answers: vec![ptr],
                        additionals: vec![srv, txt, a],
                        ..Message::default()
                    };
                    let _ = to_group.send_to(&response.encode(), mdns);
                }
                _ => {}
            }
        }
    });
    let options = Options { sap: vec![group], nmos: true, mdns: Some(mdns), ..nowhere() };
    let (discovery, changed) = start(options);
    let announcer = Announcer::new(&video_sdp(), group, Some(Ipv4Addr::LOCALHOST), 1).unwrap();
    announcer.announce().unwrap();
    let list = wait_for(&discovery, &changed, |l| l.streams.len() == 2 && l.streams[1].by.len() == 2 && !l.busy);
    assert_eq!(list.looking[1], "NMOS registries and Nodes by multicast DNS");
    let described: Vec<String> = list.streams[1].by.iter().map(Origin::describe).collect();
    assert_eq!(described, ["NMOS Node Camera 1", "SAP from 127.0.0.1"]);
}
