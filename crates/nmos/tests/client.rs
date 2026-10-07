//! The Query API client against a small registry served from the test facility.

#![cfg(feature = "client")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use st2110_nmos::client::{NodeClient, Options, QueryClient};
use st2110_nmos::{Kind, check};

const FACILITY: &str = include_str!("fixtures/facility.json");
const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const AUDIO_SENDER: &str = "5e0d0002-0000-4000-8000-000000000002";

/// A response: status, extra header lines and the body.
type Reply = (u16, String, String);

/// An HTTP server on a free port that answers each request target with `route`, which
/// is also given the port. Returns the port and the targets requested so far.
fn serve(route: impl Fn(u16, &str) -> Reply + Send + Sync + 'static) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (route, log) = (Arc::new(route), requests.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (route, log) = (route.clone(), log.clone());
            std::thread::spawn(move || handle(stream, port, &*route, &log));
        }
    });
    (port, requests)
}

fn handle(mut stream: TcpStream, port: u16, route: &dyn Fn(u16, &str) -> Reply, log: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
            break;
        }
    }
    let target = request.split_whitespace().nth(1).unwrap_or("/").to_string();
    log.lock().unwrap().push(target.clone());
    let (status, headers, body) = route(port, &target);
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Not Implemented",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    // A client that stops reading early closes the connection.
    let _ = stream.write_all(response.as_bytes());
}

/// A query parameter's value.
fn param(target: &str, name: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('=')).map(str::to_string)
}

/// A registry that pages every collection one resource at a time, except that it
/// does not page Devices and has no downgrade queries for Receivers, as some do not.
struct Registry {
    facility: Value,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Registry {
    fn start() -> (Arc<Self>, u16) {
        let facility = Arc::new(Mutex::new(Value::Null));
        let serving = facility.clone();
        let (port, requests) = serve(move |_, target| Self::route(&serving.lock().unwrap(), target));
        let mut value: Value = serde_json::from_str(FACILITY).unwrap();
        for sender in value["senders"].as_array_mut().unwrap() {
            let id = sender["id"].as_str().unwrap().to_string();
            sender["manifest_href"] = json!(format!("http://127.0.0.1:{port}/sdp/{id}"));
        }
        // The Devices' Connection APIs serve the same SDP files at /transportfile.
        for device in value["devices"].as_array_mut().unwrap() {
            device["controls"][0]["href"] = json!(format!("http://127.0.0.1:{port}/x-nmos/connection/v1.1/"));
        }
        *facility.lock().unwrap() = value.clone();
        (Arc::new(Self { facility: value, requests }), port)
    }

    fn route(facility: &Value, target: &str) -> Reply {
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        let param = |name: &str| param(target, name);
        if path == "/x-nmos/query/" {
            return (200, String::new(), json!(["v1.2/", "v1.3/", "v2.0/"]).to_string());
        }
        let transport_file = path
            .strip_prefix("/x-nmos/connection/v1.1/single/senders/")
            .and_then(|rest| rest.strip_suffix("/transportfile"));
        if let Some(id) = path.strip_prefix("/sdp/").or(transport_file) {
            let sdp = facility["manifests"][id]["sdp"].as_str();
            return match sdp {
                Some(sdp) if id == VIDEO_SENDER => (200, "Content-Type: application/sdp\r\n".into(), sdp.into()),
                _ => (404, String::new(), String::new()),
            };
        }
        let Some(collection) = path.strip_prefix("/x-nmos/query/v1.3/").map(|c| c.trim_end_matches('/')) else {
            return (404, String::new(), String::new());
        };
        if let Some((collection, id)) = collection.split_once('/') {
            if collection == "receivers" && param("query.downgrade").is_some() {
                return (501, String::new(), String::new());
            }
            let items = facility[collection].as_array().cloned().unwrap_or_default();
            return match items.into_iter().find(|item| item["id"] == id) {
                Some(item) => (200, String::new(), item.to_string()),
                None => (404, String::new(), json!({"code": 404, "error": "not found", "debug": null}).to_string()),
            };
        }
        let items = facility[collection].as_array().cloned().unwrap_or_default();
        let since = param("paging.since");
        if (collection == "devices" && since.is_some())
            || (collection == "receivers" && param("query.downgrade").is_some())
        {
            return (501, String::new(), String::new());
        }
        let Some(since) = since else {
            return (200, String::new(), Value::Array(items).to_string());
        };
        // Resource i was created at 0:i+1; a page holds those after `since`, newest first.
        let after: usize = since.strip_prefix("0:").unwrap().parse().unwrap();
        let limit: usize = param("paging.limit").unwrap().parse().unwrap();
        let end = items.len().min(after + limit);
        let mut page: Vec<Value> = items.get(after..end).unwrap_or_default().to_vec();
        page.reverse();
        let headers =
            format!("X-Paging-Limit: {limit}\r\nX-Paging-Since: 0:{after}\r\nX-Paging-Until: 0:{}\r\n", end.max(after));
        (200, headers, Value::Array(page).to_string())
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn options() -> Options {
    Options { timeout: Duration::from_secs(10), page_size: 1, env_proxy: false, ..Options::default() }
}

#[test]
fn reads_a_registry() {
    let (registry, port) = Registry::start();
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).expect("connects");
    assert_eq!(client.version(), "v1.3", "the newest version it reads, not v2.0");
    assert_eq!(client.base(), format!("http://127.0.0.1:{port}/x-nmos/query/v1.3/"));

    let snapshot = client.snapshot().expect("reads");
    for (kind, list) in [
        (Kind::Node, &snapshot.nodes),
        (Kind::Device, &snapshot.devices),
        (Kind::Source, &snapshot.sources),
        (Kind::Flow, &snapshot.flows),
        (Kind::Sender, &snapshot.senders),
        (Kind::Receiver, &snapshot.receivers),
    ] {
        assert_eq!(list, registry.facility[kind.plural()].as_array().unwrap(), "{}", kind.plural());
    }
    assert_eq!(snapshot.api_version.as_deref(), Some("v1.3"));
    assert_eq!(
        snapshot.manifests[VIDEO_SENDER].sdp.as_deref(),
        registry.facility["manifests"][VIDEO_SENDER]["sdp"].as_str()
    );
    assert_eq!(snapshot.manifests[AUDIO_SENDER].status, Some(404));
    // manifest_href names another URL, so /transportfile is fetched too.
    assert_eq!(snapshot.transport_files[VIDEO_SENDER].sdp, snapshot.manifests[VIDEO_SENDER].sdp);
    assert_eq!(
        snapshot.transport_files[VIDEO_SENDER].url,
        format!("http://127.0.0.1:{port}/x-nmos/connection/v1.1/single/senders/{VIDEO_SENDER}/transportfile")
    );
    assert_eq!(snapshot.transport_files[AUDIO_SENDER].status, Some(404));

    let requests = registry.requests();
    let asked = |text: &str| requests.iter().filter(|r| r.contains(text)).count();
    // Two nodes one per page, then an empty page.
    assert_eq!(asked("/nodes/?paging.order=create&paging.since=0:"), 3, "{requests:#?}");
    assert!(
        requests.contains(
            &"/x-nmos/query/v1.3/nodes/?paging.order=create&paging.since=0:1&paging.limit=1&query.downgrade=v1.0"
                .to_string()
        )
    );
    // Devices: paging refused, so everything at once.
    assert!(requests.contains(&"/x-nmos/query/v1.3/devices/?query.downgrade=v1.0".to_string()), "{requests:#?}");
    // Receivers: downgrade refused, with or without paging, so paging without it.
    assert!(requests.contains(&"/x-nmos/query/v1.3/receivers/?query.downgrade=v1.0".to_string()), "{requests:#?}");
    assert!(
        requests
            .contains(&"/x-nmos/query/v1.3/receivers/?paging.order=create&paging.since=0:0&paging.limit=1".to_string())
    );
    assert_eq!(asked("/receivers/"), 5, "two refused, then a page per Receiver and an empty one");

    // The audio Sender is active, so its missing SDP file is a finding.
    let rules: Vec<&str> = check(&snapshot).findings.iter().map(|f| f.rule).collect();
    assert_eq!(rules, ["manifest-unreachable"]);

    let receiver = client.resource(Kind::Receiver, "7ecf0001-0000-4000-8000-000000000001").unwrap();
    assert_eq!(receiver.as_ref(), registry.facility["receivers"].get(0));
    assert_eq!(client.resource(Kind::Receiver, "0badbeef-0000-4000-8000-000000000000").unwrap(), None);
    // Downgrade first, as for a Receiver registered at an older version, then without.
    let requests = registry.requests();
    let tail = &requests[requests.len() - 4..requests.len() - 2];
    assert_eq!(
        tail,
        [
            "/x-nmos/query/v1.3/receivers/7ecf0001-0000-4000-8000-000000000001?query.downgrade=v1.0",
            "/x-nmos/query/v1.3/receivers/7ecf0001-0000-4000-8000-000000000001"
        ]
    );
    let device = client.resource(Kind::Device, registry.facility["devices"][0]["id"].as_str().unwrap()).unwrap();
    assert_eq!(device.as_ref(), registry.facility["devices"].get(0));
    assert!(registry.requests().last().unwrap().ends_with("?query.downgrade=v1.0"), "taken with the downgrade");
}

#[test]
fn a_versioned_url_is_used_as_given() {
    let (registry, port) = Registry::start();
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}/x-nmos/query/v1.2/"), &options()).unwrap();
    assert_eq!(client.version(), "v1.2");
    assert!(registry.requests().is_empty(), "no discovery request");
    let error = QueryClient::connect(&format!("http://127.0.0.1:{port}/x-nmos/query/v9.9"), &options()).unwrap_err();
    assert!(error.message.contains("v9.9 is not an IS-04 version"), "{error}");
}

#[test]
fn failures_name_the_url() {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let error = QueryClient::connect(&format!("http://127.0.0.1:{unused}"), &options()).unwrap_err();
    assert_eq!(error.url, format!("http://127.0.0.1:{unused}/x-nmos/query/"));
    assert!(QueryClient::connect("registry.example", &options()).is_err());
    assert!(QueryClient::connect("ftp://registry.example", &options()).is_err());

    let (_, port) = Registry::start();
    let error = QueryClient::connect(&format!("http://127.0.0.1:{port}/elsewhere"), &options()).unwrap_err();
    assert!(error.to_string().contains("HTTP 404: no IS-04 Query API here"), "{error}");
}

/// Five Nodes, created at 0:1 to 0:5 and last updated in the same order.
fn five_nodes() -> Vec<Value> {
    (1..=5)
        .map(|i| json!({"id": format!("00000000-0000-4000-8000-00000000000{i}"), "label": format!("node {i}")}))
        .collect()
}

fn node_ids(nodes: &[Value]) -> Vec<&str> {
    let mut ids: Vec<&str> = nodes.iter().map(|n| n["id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    ids
}

#[test]
fn reads_every_page_of_a_registry_that_pages_unasked() {
    // It refuses creation order, but pages every query itself, newest first, two at a
    // time: IS-04 lets a server choose its own default limit.
    let (port, requests) = serve(|_, target| {
        if target == "/x-nmos/query/" {
            return (200, String::new(), json!(["v1.3/"]).to_string());
        }
        if param(target, "paging.order").is_some() {
            return (501, String::new(), String::new());
        }
        let until: usize = param(target, "paging.until").map_or(5, |u| u.strip_prefix("0:").unwrap().parse().unwrap());
        let since = until.saturating_sub(2);
        let mut page: Vec<Value> = five_nodes().drain(since..until).collect();
        page.reverse();
        let headers = format!("X-Paging-Limit: 2\r\nX-Paging-Since: 0:{since}\r\nX-Paging-Until: 0:{until}\r\n");
        (200, headers, Value::Array(page).to_string())
    });
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).unwrap();
    let nodes = client.list(Kind::Node).expect("reads");
    assert_eq!(node_ids(&nodes), node_ids(&five_nodes()));
    let requests = requests.lock().unwrap().clone();
    assert!(requests.contains(&"/x-nmos/query/v1.3/nodes/?paging.until=0:1&query.downgrade=v1.0".to_string()));
    assert_eq!(requests.len(), 1 + 1 + 4, "the discovery, the refused query, then pages until an empty one");
}

#[test]
fn stops_when_paging_goes_round_in_circles() {
    // Ignores paging.since, so every page is the first, with a new X-Paging-Until.
    let calls = Mutex::new(0);
    let (port, requests) = serve(move |_, target| {
        if target == "/x-nmos/query/" {
            return (200, String::new(), json!(["v1.3/"]).to_string());
        }
        let mut calls = calls.lock().unwrap();
        *calls += 1;
        let headers = format!("X-Paging-Limit: 2\r\nX-Paging-Until: 1790510437:{calls}\r\n");
        (200, headers, Value::Array(five_nodes()[..2].to_vec()).to_string())
    });
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).unwrap();
    let error = client.list(Kind::Node).unwrap_err();
    assert!(error.message.contains("paging cursors do not advance"), "{error}");
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[test]
fn asks_a_v1_0_registry_for_everything_plainly() {
    // IS-04 v1.0 has no paging or downgrade; this one reads any parameter as a filter.
    let (port, requests) = serve(|_, target| match target {
        "/x-nmos/query/" => (200, String::new(), json!(["v1.0/"]).to_string()),
        _ if target.contains('?') => (200, String::new(), "[]".into()),
        _ => (200, String::new(), Value::Array(five_nodes()).to_string()),
    });
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).unwrap();
    assert_eq!(client.version(), "v1.0");
    assert_eq!(client.list(Kind::Node).unwrap().len(), 5);
    assert_eq!(*requests.lock().unwrap(), ["/x-nmos/query/", "/x-nmos/query/v1.0/nodes/"]);
}

#[test]
fn fetches_sdp_files_within_bounds() {
    let (port, _) = serve(|port, target| {
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        match path {
            "/x-nmos/query/" => (200, String::new(), json!(["v1.3/"]).to_string()),
            "/x-nmos/query/v1.3/senders/" => {
                // The scheme is case-insensitive (RFC 3986 §3.1).
                let sender = json!({"id": VIDEO_SENDER, "transport": "urn:x-nmos:transport:rtp.mcast",
                    "manifest_href": format!("HTTP://127.0.0.1:{port}/sdp")});
                (200, String::new(), json!([sender]).to_string())
            }
            "/sdp" => (200, String::new(), "v=0\r\n".into()),
            "/huge" => (200, String::new(), "a".repeat((1 << 20) + 1)),
            _ => (200, String::new(), "[]".into()),
        }
    });
    let client = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).unwrap();
    let snapshot = client.snapshot().unwrap();
    assert_eq!(snapshot.manifests[VIDEO_SENDER].sdp.as_deref(), Some("v=0\r\n"));
    let huge = client.manifest(&format!("http://127.0.0.1:{port}/huge"));
    assert_eq!(huge.sdp, None);
    assert!(huge.error.is_some_and(|e| e.starts_with("reading the response")));
}

/// The test facility's Camera 1 as a Node API serves it, its SDP files beside it.
fn camera_node(port: u16, target: &str) -> Reply {
    let mut facility: Value = serde_json::from_str(FACILITY).unwrap();
    let node = facility["nodes"][0].clone();
    let mine = |collection: &str, key: &str, id: &Value| -> Vec<Value> {
        let items = facility[collection].as_array().unwrap();
        items.iter().filter(|item| &item[key] == id).cloned().collect()
    };
    let mut devices = mine("devices", "node_id", &node["id"]);
    devices[0]["controls"][0]["href"] = json!(format!("http://127.0.0.1:{port}/x-nmos/connection/v1.1/"));
    let device = &devices[0]["id"].clone();
    let (sources, flows, receivers) = (
        mine("sources", "device_id", device),
        mine("flows", "device_id", device),
        mine("receivers", "device_id", device),
    );
    let mut senders = mine("senders", "device_id", device);
    for sender in &mut senders {
        let id = sender["id"].as_str().unwrap().to_string();
        sender["manifest_href"] = json!(format!("http://127.0.0.1:{port}/sdp/{id}"));
    }
    let json = |value: Value| (200, String::new(), value.to_string());
    match target {
        "/x-nmos/node/" => json(json!(["v1.0/", "v1.1/", "v1.2/", "v1.3/"])),
        "/x-nmos/node/v1.3/self/" => json(node),
        "/x-nmos/node/v1.3/devices/" => json(Value::Array(devices)),
        "/x-nmos/node/v1.3/sources/" => json(Value::Array(sources)),
        "/x-nmos/node/v1.3/flows/" => json(Value::Array(flows)),
        "/x-nmos/node/v1.3/senders/" => json(Value::Array(senders)),
        "/x-nmos/node/v1.3/receivers/" => json(Value::Array(receivers)),
        _ => {
            let transport_file = target
                .strip_prefix("/x-nmos/connection/v1.1/single/senders/")
                .and_then(|rest| rest.strip_suffix("/transportfile"));
            match target.strip_prefix("/sdp/").or(transport_file).map(|id| facility["manifests"][id]["sdp"].take()) {
                Some(Value::String(sdp)) => (200, String::new(), sdp),
                _ => (404, String::new(), String::new()),
            }
        }
    }
}

#[test]
fn reads_a_node() {
    let (port, requests) = serve(camera_node);
    let node = NodeClient::connect(&format!("http://127.0.0.1:{port}"), &options()).expect("connects");
    assert_eq!((node.version(), node.base()), ("v1.3", format!("http://127.0.0.1:{port}/x-nmos/node/v1.3/").as_str()));
    let snapshot = node.snapshot().expect("reads");
    assert_eq!(snapshot.source.as_deref(), Some(node.base()));
    let labels = |list: &[Value]| list.iter().map(|r| r["label"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(labels(&snapshot.nodes), ["Camera 1"]);
    assert_eq!(labels(&snapshot.devices), ["Camera 1"]);
    assert_eq!(labels(&snapshot.senders), ["CAM 1 video", "CAM 1 audio"]);
    assert_eq!((snapshot.flows.len(), snapshot.sources.len(), snapshot.receivers.len()), (2, 2, 0));
    let facility: Value = serde_json::from_str(FACILITY).unwrap();
    for id in [VIDEO_SENDER, AUDIO_SENDER] {
        assert_eq!(snapshot.manifests[id].sdp.as_deref(), facility["manifests"][id]["sdp"].as_str());
        assert_eq!(snapshot.transport_files[id].sdp, snapshot.manifests[id].sdp);
    }
    // Read as a registry is, it passes the same checks.
    assert_eq!(check(&snapshot).findings.iter().map(|f| f.rule).collect::<Vec<_>>(), Vec::<&str>::new());
    assert_eq!(requests.lock().unwrap()[0], "/x-nmos/node/");

    let versioned = NodeClient::connect(&format!("http://127.0.0.1:{port}/x-nmos/node/v1.3"), &options()).unwrap();
    assert_eq!(versioned.base(), node.base());
    let error = QueryClient::connect(&format!("http://127.0.0.1:{port}"), &options()).unwrap_err();
    assert!(error.to_string().contains("HTTP 404: no IS-04 Query API here"), "{error}");
    let unused = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let error = NodeClient::connect(&format!("http://127.0.0.1:{unused}"), &options()).unwrap_err();
    assert_eq!(error.url, format!("http://127.0.0.1:{unused}/x-nmos/node/"));
}
