//! `st2110 router --demo`: the page, its API and the demo facility, over HTTP, as a
//! browser and other tools reach them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

/// The router, serving the demo facility on a free port; stopped when dropped.
struct Router {
    child: Child,
    /// Its standard output, kept open so that it can go on writing.
    _stdout: BufReader<ChildStdout>,
    /// `127.0.0.1:<port>`.
    address: String,
}

impl Router {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_st2110"))
            .args(["router", "--demo", "--listen", "127.0.0.1:0", "--lead", "0.5"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("runs");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("prints where it is");
        let address = line
            .trim()
            .strip_prefix("Router: http://")
            .and_then(|rest| rest.strip_suffix('/'))
            .unwrap_or_else(|| panic!("no address in {line:?}"))
            .to_string();
        Self { child, _stdout: stdout, address }
    }

    /// Sends a request, and returns the status and body.
    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(&self.address).expect("connects");
        let mut request = format!("{method} {path} HTTP/1.1\r\nContent-Length: {}\r\n", body.len());
        if !headers.iter().any(|(name, _)| *name == "Host") {
            request.push_str(&format!("Host: {}\r\n", self.address));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        stream.write_all(request.as_bytes()).expect("sends");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("answers");
        let (head, body) = response.split_once("\r\n\r\n").expect("a response");
        let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status");
        (status, body.to_string())
    }

    fn get(&self, path: &str) -> Value {
        let (status, body) = self.request("GET", path, &[], "");
        assert_eq!(status, 200, "{path}: {body}");
        serde_json::from_str(&body).expect("JSON")
    }

    fn take(&self, routes: Value) -> Value {
        let body = json!({"routes": routes}).to_string();
        let origin = format!("http://{}", self.address);
        let headers = [("Content-Type", "application/json"), ("Origin", origin.as_str())];
        let (status, body) = self.request("POST", "/api/take", &headers, &body);
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).expect("JSON")
    }

    /// Each Receiver's label, and the label of the Sender it takes now.
    fn routes(&self) -> Vec<(String, Option<String>)> {
        let state = self.get("/api/state");
        state["receivers"]
            .as_array()
            .expect("receivers")
            .iter()
            .map(|r| {
                let sender =
                    r["current"].as_u64().map(|i| state["senders"][i as usize]["label"].as_str().unwrap().into());
                (r["label"].as_str().unwrap().to_string(), sender)
            })
            .collect()
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn taking(routes: &[(String, Option<String>)], receiver: &str) -> Option<String> {
    routes.iter().find(|(r, _)| r == receiver).and_then(|(_, s)| s.clone())
}

#[test]
fn serves_the_page_and_the_demo_registry() {
    let router = Router::start();
    let (status, page) = router.request("GET", "/", &[], "");
    assert_eq!(status, 200);
    assert!(page.contains("<title>ST 2110 Router</title>"));

    let state = router.get("/api/state");
    assert_eq!(state["demo"], true);
    assert_eq!(state["senders"].as_array().unwrap().len(), 9);
    assert_eq!(state["receivers"].as_array().unwrap().len(), 8);
    let routes = router.routes();
    assert_eq!(taking(&routes, "MON 1 video").as_deref(), Some("CAM 1 video"));
    assert_eq!(taking(&routes, "MON 3 video"), None);

    // The demo is a registry like any other: `st2110 connect` lists it.
    let output = Command::new(env!("CARGO_BIN_EXE_st2110"))
        .args(["connect", &format!("http://{}", router.address)])
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .output()
        .expect("runs");
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("receiver \"MON 4 video\""), "{text}");
}

#[test]
fn takes_one_route_and_a_salvo() {
    let router = Router::start();
    let one = router.take(json!([{"receiver": "MON 3 video", "sender": "CAM 2 video"}]));
    assert_eq!(one["succeeded"], true, "{one:#}");
    assert_eq!(one["activation"]["mode"], "activate_immediate");
    assert_eq!(taking(&router.routes(), "MON 3 video").as_deref(), Some("CAM 2 video"));

    let salvo = router.take(json!([
        {"receiver": "MON 1 video", "sender": "CAM 4 video"},
        {"receiver": "MON 1 audio", "sender": "CAM 4 audio"},
        {"receiver": "MON 2 video", "sender": null},
    ]));
    assert_eq!(salvo["succeeded"], true, "{salvo:#}");
    assert_eq!(salvo["activation"]["mode"], "activate_scheduled_absolute");
    let states: Vec<&str> =
        salvo["connections"].as_array().unwrap().iter().map(|c| c["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["done", "done", "done"]);
    let routes = router.routes();
    assert_eq!(taking(&routes, "MON 1 video").as_deref(), Some("CAM 4 video"));
    assert_eq!(taking(&routes, "MON 1 audio").as_deref(), Some("CAM 4 audio"));
    assert_eq!(taking(&routes, "MON 2 video"), None);
}

#[test]
fn refuses_what_a_receiver_cannot_take_and_says_why() {
    let router = Router::start();
    let refused = router.take(json!([{"receiver": "MON 4 video", "sender": "CAM 1 video"}]));
    assert_eq!(refused["succeeded"], false);
    assert_eq!(refused["connections"][0]["state"], "refused");
    assert_eq!(taking(&router.routes(), "MON 4 video"), None);

    let state = router.get("/api/state");
    let id = |list: &str, label: &str| {
        state[list].as_array().unwrap().iter().find(|r| r["label"] == label).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let why = router.get(&format!(
        "/api/why?sender={}&receiver={}",
        id("senders", "CAM 1 video"),
        id("receivers", "MON 4 video")
    ));
    assert_eq!(why["fits"], false);
    assert!(why["reason"].as_str().unwrap().contains("frame_height 1080 is not one of 720"), "{why}");
}

#[test]
fn takes_connections_only_from_its_own_page() {
    let router = Router::start();
    let body = json!({"routes": [{"receiver": "MON 3 video", "sender": "CAM 2 video"}]}).to_string();
    let json_type = ("Content-Type", "application/json");
    // A form or a simple request from another site.
    let (status, _) = router.request("POST", "/api/take", &[("Content-Type", "text/plain")], &body);
    assert_eq!(status, 403);
    let (status, _) = router.request("POST", "/api/take", &[json_type, ("Origin", "http://evil.example")], &body);
    assert_eq!(status, 403);
    let (status, _) = router.request("POST", "/api/take", &[json_type, ("Sec-Fetch-Site", "cross-site")], &body);
    assert_eq!(status, 403);
    // Another site's name pointed at this machine.
    let (status, _) = router.request("GET", "/api/state", &[("Host", "evil.example")], "");
    assert_eq!(status, 403);
    let (status, _) = router.request("GET", "/api/take", &[], "");
    assert_eq!(status, 405);
    assert_eq!(taking(&router.routes(), "MON 3 video"), None);
}

#[test]
fn needs_a_registry_or_the_demo() {
    let output = Command::new(env!("CARGO_BIN_EXE_st2110")).args(["router"]).output().expect("runs");
    assert_eq!(output.status.code(), Some(2));
    let output = Command::new(env!("CARGO_BIN_EXE_st2110"))
        .args(["router", "registry.example", "--listen", "127.0.0.1:0"])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a registry's http:// or https:// URL"));
}
