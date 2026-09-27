//! The Query API client against a small registry served from the test facility.

#![cfg(feature = "client")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use st2110_nmos::client::{Options, QueryClient};
use st2110_nmos::{Kind, check};

const FACILITY: &str = include_str!("fixtures/facility.json");
const VIDEO_SENDER: &str = "5e0d0001-0000-4000-8000-000000000001";
const AUDIO_SENDER: &str = "5e0d0002-0000-4000-8000-000000000002";

/// A registry that pages every collection one resource at a time, except that it
/// does not page Devices and has no downgrade queries for Receivers, as some do not.
struct Registry {
    facility: Value,
    requests: Mutex<Vec<String>>,
}

impl Registry {
    fn start() -> (Arc<Self>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().unwrap().port();
        let mut facility: Value = serde_json::from_str(FACILITY).unwrap();
        for sender in facility["senders"].as_array_mut().unwrap() {
            let id = sender["id"].as_str().unwrap().to_string();
            sender["manifest_href"] = json!(format!("http://127.0.0.1:{port}/sdp/{id}"));
        }
        let registry = Arc::new(Self { facility, requests: Mutex::new(Vec::new()) });
        let serving = registry.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let registry = serving.clone();
                std::thread::spawn(move || registry.handle(stream));
            }
        });
        (registry, port)
    }

    fn handle(&self, mut stream: TcpStream) {
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
        self.requests.lock().unwrap().push(target.clone());
        let (status, headers, body) = self.route(&target);
        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            _ => "Not Implemented",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    fn route(&self, target: &str) -> (u16, String, String) {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let param = |name: &str| {
            query.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('=')).map(str::to_string)
        };
        if path == "/x-nmos/query/" {
            return (200, String::new(), json!(["v1.2/", "v1.3/", "v2.0/"]).to_string());
        }
        if let Some(id) = path.strip_prefix("/sdp/") {
            let sdp = self.facility["manifests"][id]["sdp"].as_str();
            return match sdp {
                Some(sdp) if id == VIDEO_SENDER => (200, "Content-Type: application/sdp\r\n".into(), sdp.into()),
                _ => (404, String::new(), String::new()),
            };
        }
        let Some(collection) = path.strip_prefix("/x-nmos/query/v1.3/").map(|c| c.trim_end_matches('/')) else {
            return (404, String::new(), String::new());
        };
        let items = self.facility[collection].as_array().cloned().unwrap_or_default();
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
