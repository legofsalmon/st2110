//! `st2110 router --demo`: the page, its API and the demo facility, over HTTP, as a
//! browser and other tools reach them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_nmos::ws;

/// The router, serving the demo facility on a free port; stopped when dropped.
struct Router {
    child: Child,
    /// Its standard output, kept open so that it can go on writing.
    _stdout: BufReader<ChildStdout>,
    /// `127.0.0.1:<port>`.
    address: String,
}

impl Router {
    /// Without previews, so that the demo sends no streams: only one test at a time
    /// should, since every demo sends to the same multicast groups.
    fn start() -> Self {
        Self::with(&["--previews", "0", "--no-state"])
    }

    fn with(more: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_st2110"))
            .args(["router", "--demo", "--listen", "127.0.0.1:0", "--lead", "0.5"])
            .args(more)
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
        let (status, _, body) = self.bytes(method, path, headers, body);
        (status, String::from_utf8(body).expect("text"))
    }

    /// Sends a request, and returns the status, the head and the body.
    fn bytes(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String, Vec<u8>) {
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
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("answers");
        let end = response.windows(4).position(|w| w == b"\r\n\r\n").expect("a response");
        let head = String::from_utf8(response[..end].to_vec()).expect("a head");
        let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status");
        (status, head, response[end + 4..].to_vec())
    }

    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let origin = format!("http://{}", self.address);
        let headers = [("Content-Type", "application/json"), ("Origin", origin.as_str())];
        let (status, body) = self.request("POST", path, &headers, &body.to_string());
        (status, serde_json::from_str(&body).expect("JSON"))
    }

    fn get(&self, path: &str) -> Value {
        let (status, body) = self.request("GET", path, &[], "");
        assert_eq!(status, 200, "{path}: {body}");
        serde_json::from_str(&body).expect("JSON")
    }

    fn take(&self, routes: Value) -> Value {
        let (status, body) = self.post("/api/take", &json!({"routes": routes}));
        assert_eq!(status, 200, "{body}");
        body
    }

    /// A Sender's id, by its label.
    fn sender(&self, label: &str) -> String {
        let state = self.get("/api/state");
        let senders = state["senders"].as_array().expect("senders");
        senders.iter().find(|s| s["label"] == label).expect("a sender")["id"].as_str().unwrap().into()
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
    assert_eq!(state["senders"].as_array().unwrap().len(), 10);
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

/// With `group`, a monitor's audio follows its video from the camera's group
/// (BCP-002-01), and disconnects with it; what of a group is left as it is, says why.
#[test]
fn takes_a_monitors_group_from_a_cameras() {
    let router = Router::start();
    let state = router.get("/api/state");
    let mon3 = state["receivers"].as_array().unwrap().iter().find(|r| r["label"] == "MON 3 audio").unwrap();
    assert_eq!((&mon3["group"]["name"], &mon3["group"]["role"]), (&json!("Monitor 3"), &json!("Audio 1")));
    let (status, grouped) = router
        .post("/api/take", &json!({"routes": [{"receiver": "MON 3 video", "sender": "CAM 2 video"}], "group": true}));
    assert_eq!((status, &grouped["succeeded"]), (200, &json!(true)), "{grouped:#}");
    assert_eq!(grouped["activation"]["mode"], "activate_scheduled_absolute", "the two switch together");
    let routes = router.routes();
    assert_eq!(taking(&routes, "MON 3 video").as_deref(), Some("CAM 2 video"));
    assert_eq!(taking(&routes, "MON 3 audio").as_deref(), Some("CAM 2 audio"));

    let (_, off) =
        router.post("/api/take", &json!({"routes": [{"receiver": "MON 3 audio", "sender": null}], "group": true}));
    assert_eq!(off["connections"].as_array().unwrap().len(), 2, "{off:#}");
    let routes = router.routes();
    assert_eq!((taking(&routes, "MON 3 video"), taking(&routes, "MON 3 audio")), (None, None));

    // The graphics Node gives no group, so the monitor's audio is left as it is.
    let (_, gfx) = router
        .post("/api/take", &json!({"routes": [{"receiver": "MON 4 video", "sender": "GFX 1 video"}], "group": true}));
    assert_eq!(gfx["connections"].as_array().unwrap().len(), 1, "{gfx:#}");
    assert!(gfx["notes"][0].as_str().unwrap().starts_with("MON 4 audio left as it is"), "{gfx:#}");
    let log = router.get("/api/log");
    assert!(log.to_string().contains("MON 4 audio left as it is"), "the log keeps it");
}

/// `st2110 connect --group` takes the same group, here only checked.
#[test]
fn connect_takes_a_group_too() {
    let router = Router::start();
    let output = Command::new(env!("CARGO_BIN_EXE_st2110"))
        .args(["connect", &format!("http://{}", router.address), "--receiver", "MON 3 video"])
        .args(["--sender", "CAM 3 video", "--group", "--dry-run"])
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .output()
        .expect("runs");
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{text}{}", String::from_utf8_lossy(&output.stderr));
    assert!(text.contains("receiver \"MON 3 audio\""), "{text}");
    assert!(text.contains("CAM 3 audio"), "{text}");
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
    assert!(why["reason"].as_str().unwrap().contains("frame_height 270 is not one of 180"), "{why}");
}

#[test]
fn turns_a_sender_off_and_sends_it_elsewhere() {
    let router = Router::start();
    let camera = router.sender("CAM 3 video");
    let enabled = |router: &Router| {
        let state = router.get("/api/state");
        state["senders"].as_array().unwrap().iter().find(|s| s["id"] == camera.as_str()).unwrap()["enabled"].clone()
    };
    assert_eq!(enabled(&router), true);
    let stream = router.get(&format!("/api/stream?sender={camera}"));
    assert_eq!(stream["active"]["master_enable"], true, "{stream:#}");
    assert_eq!(stream["active"]["transport_params"][0]["destination_ip"], "239.10.3.1", "{stream:#}");

    let (status, off) = router.post("/api/sender", &json!({"sender": camera, "enable": false}));
    assert_eq!(status, 200, "{off:#}");
    assert_eq!(off["succeeded"], true, "{off:#}");
    assert_eq!(off["state"], "done");
    assert!(off["describe"].as_str().unwrap().ends_with(": off: done"), "{off:#}");
    assert_eq!(enabled(&router), false);

    // Turned on again, to other groups; a leg past the last one given is turned off.
    let (status, moved) =
        router.post("/api/sender", &json!({"sender": camera, "enable": true, "destinations": ["239.10.3.9:5006"]}));
    assert_eq!(status, 200, "{moved:#}");
    assert_eq!(moved["succeeded"], true, "{moved:#}");
    let stream = router.get(&format!("/api/stream?sender={camera}"));
    let legs = &stream["active"]["transport_params"];
    assert_eq!(legs[0]["destination_ip"], "239.10.3.9", "{stream:#}");
    assert_eq!(legs[0]["destination_port"], 5006);
    assert_eq!(legs[1]["rtp_enabled"], false);
    assert_eq!(enabled(&router), true);
    // Both are in the log, as takes are.
    assert_eq!(router.get("/api/log")["log"].as_array().unwrap().len(), 2);

    // A unicast address on a multicast Sender is refused, and a bad one named.
    let (_, refused) =
        router.post("/api/sender", &json!({"sender": camera, "enable": true, "destinations": ["192.168.10.31:5004"]}));
    assert_eq!(refused["state"], "refused", "{refused:#}");
    let (status, bad) =
        router.post("/api/sender", &json!({"sender": camera, "enable": true, "destinations": ["239.10"]}));
    assert_eq!(status, 400);
    assert!(bad["error"].as_str().unwrap().starts_with("leg 1: "), "{bad:#}");
    // Only from the page.
    let headers = [("Content-Type", "application/json"), ("Origin", "http://evil.example")];
    let body = json!({"sender": camera, "enable": false}).to_string();
    assert_eq!(router.request("POST", "/api/sender", &headers, &body).0, 403);
    assert_eq!(enabled(&router), true);
}

#[test]
fn previews_the_demo_streams_and_describes_them() {
    let router = Router::with(&["--no-state"]);
    let camera = router.sender("CAM 2 video");
    let sound = router.sender("CAM 2 audio");
    let (status, watching) = router.post("/api/watch", &json!({"senders": [camera, sound]}));
    assert_eq!(status, 200, "{watching}");
    assert_eq!(watching["refused"], json!({}));

    // The demo sends each camera's stream on this machine, and the router receives it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let live = loop {
        let live = router.get("/api/live");
        let pictures = live["senders"][&camera]["pictures"].as_u64().unwrap_or(0);
        let levels = live["senders"][&sound]["levels"].as_array().map_or(0, Vec::len);
        if pictures > 0 && levels == 2 {
            break live;
        }
        assert!(std::time::Instant::now() < deadline, "no previews: {live:#}");
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert_eq!(live["senders"][&camera]["size"], json!([480, 270]), "{live:#}");
    // CAM 2 sounds at -12 dBFS.
    let level = live["senders"][&sound]["levels"][0].as_f64().expect("a level");
    assert!((level + 12.0).abs() < 0.5, "{level}");

    let (status, head, png) = router.bytes("GET", &format!("/api/preview?sender={camera}"), &[], "");
    assert_eq!(status, 200);
    assert!(head.contains("Content-Type: image/png"), "{head}");
    assert_eq!(&png[1..4], b"PNG");

    let stream = router.get(&format!("/api/stream?sender={camera}"));
    assert_eq!(stream["device"], "Camera 2");
    assert_eq!(stream["receivers"], json!(["MON 2 video"]));
    assert_eq!(stream["streams"].as_array().unwrap().len(), 2, "an ST 2022-7 pair");
    assert!(stream["sdp"].as_str().unwrap().contains("a=fmtp:96"), "{stream:#}");
    assert_eq!(router.request("GET", "/api/stream?sender=nobody", &[], "").0, 404);

    // Another site cannot ask for previews.
    let headers = [("Content-Type", "application/json"), ("Origin", "http://evil.example")];
    let (status, _) = router.request("POST", "/api/watch", &headers, r#"{"senders": []}"#);
    assert_eq!(status, 403);
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

impl Router {
    /// The page's WebSocket, as its page opens it.
    fn events(&self) -> ws::Socket {
        let origin = format!("http://{}", self.address);
        let socket = ws::connect(
            &format!("ws://{}/api/events", self.address),
            &[("Origin", origin.as_str())],
            Duration::from_secs(5),
        )
        .expect("connects");
        socket.set_read_timeout(Some(Duration::from_secs(10))).expect("a timeout");
        socket
    }
}

/// The next message of `kind` on the page's WebSocket.
fn next(socket: &mut ws::Socket, kind: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "no {kind} message");
        let text = socket.read().expect("a message").expect("still open");
        let message: Value = serde_json::from_str(&text).expect("JSON");
        if message["type"] == kind {
            return message;
        }
    }
}

fn label_of(state: &Value, receiver: &str) -> Option<String> {
    let r = state["receivers"].as_array()?.iter().find(|r| r["label"] == receiver)?;
    Some(state["senders"][r["current"].as_u64()? as usize]["label"].as_str()?.to_string())
}

#[test]
fn pushes_changes_to_the_page_as_they_happen() {
    let router = Router::start();
    let mut socket = router.events();
    let hello = next(&mut socket, "hello");
    assert_eq!(hello["log"], json!([]));
    let state = next(&mut socket, "state");
    assert_eq!(label_of(&state, "MON 1 video").as_deref(), Some("CAM 1 video"));

    // The router subscribes to the demo registry, and says so once every subscription is up.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !router.get("/api/state")["subscribed"].as_bool().unwrap() {
        assert!(Instant::now() < deadline, "the router never subscribed to the registry");
        std::thread::sleep(Duration::from_millis(100));
    }

    // A take from anywhere reaches the page: its log entry, then the registry's change,
    // which the registry pushes to the router.
    let taken = router.take(json!([{"receiver": "MON 3 video", "sender": "CAM 2 video"}]));
    let entry = next(&mut socket, "log")["entry"].clone();
    assert_eq!(entry["id"], taken["log_id"]);
    assert_eq!(entry["succeeded"], true);
    assert!(entry["connections"][0]["describe"].as_str().unwrap().contains("MON 3 video"), "{entry}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = next(&mut socket, "state");
        if label_of(&state, "MON 3 video").as_deref() == Some("CAM 2 video") {
            break;
        }
        assert!(Instant::now() < deadline, "the change never reached the page");
    }
    assert_eq!(router.get("/api/log")["log"][0]["id"], taken["log_id"]);
    socket.close();

    // Another site's page cannot listen.
    let refused = ws::connect(
        &format!("ws://{}/api/events", router.address),
        &[("Origin", "http://evil.example")],
        Duration::from_secs(5),
    );
    assert!(refused.is_err());
}

#[test]
fn the_demo_registry_pushes_its_changes_to_subscriptions() {
    let router = Router::start();
    let (status, subscription) = router.post(
        "/x-nmos/query/v1.3/subscriptions",
        &json!({"max_update_rate_ms": 100, "resource_path": "/receivers", "params": {}, "persist": false, "secure": false}),
    );
    assert_eq!(status, 201, "{subscription}");
    let mut socket = ws::connect(subscription["ws_href"].as_str().unwrap(), &[], Duration::from_secs(5)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let sync: Value = serde_json::from_str(&socket.read().unwrap().unwrap()).unwrap();
    assert_eq!(sync["grain"]["topic"], "/receivers/");
    assert_eq!(sync["grain"]["data"].as_array().unwrap().len(), 8);
    router.take(json!([{"receiver": "MON 3 audio", "sender": "CAM 3 audio"}]));
    let change: Value = serde_json::from_str(&socket.read().unwrap().unwrap()).unwrap();
    let data = &change["grain"]["data"][0];
    assert_eq!(data["pre"]["subscription"]["sender_id"], Value::Null);
    assert_eq!(data["post"]["subscription"]["active"], true);
}

#[test]
fn asks_for_is_10_tokens_with_demo_auth() {
    let router = Router::with(&["--previews", "0", "--no-state", "--demo-auth"]);
    // The demo registry and Connection APIs refuse requests without a token…
    let (status, _) = router.request("GET", "/x-nmos/query/v1.3/senders", &[], "");
    assert_eq!(status, 401);
    let (status, head, _) = router.bytes("GET", "/x-nmos/query/v1.3/senders", &[("Authorization", "Bearer guess")], "");
    assert_eq!(status, 401);
    assert!(head.contains("WWW-Authenticate: Bearer"), "{head}");
    // …and its Authorization Server hands them only to its client.
    let (status, _) = router.request(
        "POST",
        "/x-nmos/auth/v1.0/token",
        &[("Content-Type", "application/x-www-form-urlencoded"), ("Authorization", "Basic d3Jvbmc6d3Jvbmc=")],
        "grant_type=client_credentials",
    );
    assert_eq!(status, 401);

    // The router gets its own, and reads and switches as before.
    assert_eq!(taking(&router.routes(), "MON 1 video").as_deref(), Some("CAM 1 video"));
    let one = router.take(json!([{"receiver": "MON 3 video", "sender": "CAM 2 video"}]));
    assert_eq!(one["succeeded"], true, "{one:#}");
    // It registered itself for private_key_jwt, and publishes its key.
    let auth = router.get("/api/state")["auth"].as_str().unwrap().to_string();
    assert!(auth.contains("signing with its key"), "{auth}");
    assert_eq!(router.get("/.well-known/jwks.json")["keys"][0]["alg"], "ES256");
    let mut socket = router.events();
    next(&mut socket, "state");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !router.get("/api/state")["subscribed"].as_bool().unwrap() {
        assert!(Instant::now() < deadline, "the router never subscribed with its token");
        std::thread::sleep(Duration::from_millis(100));
    }

    // So do `st2110 nmos` and `st2110 connect`, given the client's id and secret.
    let base = format!("http://{}", router.address);
    let run = |args: &[&str], secret: &str| {
        Command::new(env!("CARGO_BIN_EXE_st2110"))
            .args(args)
            .args(["--auth", &format!("{base}/"), "--client-id", "st2110-demo"])
            .env("ST2110_CLIENT_SECRET", secret)
            .env("NO_COLOR", "1")
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1")
            .output()
            .expect("runs")
    };
    let listed = run(&["connect", &base], "demo-secret");
    let text = String::from_utf8_lossy(&listed.stdout);
    assert_eq!(listed.status.code(), Some(0), "{text}{}", String::from_utf8_lossy(&listed.stderr));
    assert!(text.contains("MON 4 video"), "{text}");
    let made = run(&["connect", &base, "--receiver", "MON 3 audio", "--sender", "CAM 2 audio"], "demo-secret");
    assert_eq!(made.status.code(), Some(0), "{}", String::from_utf8_lossy(&made.stdout));
    let wrong = run(&["nmos", &base, "--quiet"], "not-the-secret");
    assert_eq!(wrong.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("invalid_client"),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
}

/// `st2110 connect` with no registry named finds the demo's by unicast DNS-SD, and
/// with --register finds its Authorization Server the same way, registers by RFC 7591
/// with the initial access token, and keeps the registration for the next run.
#[test]
fn finds_the_demo_by_dns_sd_and_registers_with_its_authorization_server() {
    let router = Router::with(&["--previews", "0", "--no-state", "--demo-auth"]);
    let file = StateFile::new("clients");
    let clients = file.0.with_file_name("clients.json");
    let run = |more: &[&str], registration: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_st2110"))
            .args(["connect", "--dns-server", &router.address, "--domain", "demo.test"])
            .args(more)
            .env("ST2110_REGISTRATION_TOKEN", registration)
            .env("NO_COLOR", "1")
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1")
            .output()
            .expect("runs");
        let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        (output.status.code(), text)
    };
    let register = ["--register", "--client-file", clients.to_str().unwrap()];
    let (code, text) = run(&register, "demo-registration");
    assert_eq!(code, Some(0), "{text}");
    let base = format!("http://{}", router.address);
    assert!(text.contains(&format!("Registry: {base} (st2110 demo registry, found by DNS in demo.test)")), "{text}");
    assert!(text.contains(&format!("Authorization Server: {base}/ (")), "{text}");
    assert!(text.contains("Registered with"), "{text}");
    assert!(text.contains("receiver \"MON 4 video\""), "{text}");
    let kept = std::fs::read_to_string(&clients).unwrap();
    assert!(kept.contains("client_secret"), "{kept}");
    // Kept, so not registered again.
    let (code, text) = run(&register, "");
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("Registered with"), "{text}");
    // Without the initial access token, the demo registers no one.
    let (code, text) = run(&["--register", "--client-file", file.0.with_file_name("other.json").to_str().unwrap()], "");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("invalid_token"), "{text}");
}

/// A state file of its own, removed when dropped.
struct StateFile(PathBuf);

impl StateFile {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("st2110-router-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir.join("router.json"))
    }
}

impl Drop for StateFile {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[test]
fn keeps_its_log_and_the_demo_connections_across_a_restart() {
    let file = StateFile::new("restart");
    let path = file.0.to_str().unwrap();
    let first = Router::with(&["--previews", "0", "--state", path]);
    let taken = first.take(json!([{"receiver": "MON 3 video", "sender": "CAM 3 video"}]));
    assert_eq!(taken["succeeded"], true, "{taken:#}");
    first.take(json!([{"receiver": "MON 1 video", "sender": null}]));
    drop(first);

    let second = Router::with(&["--previews", "0", "--state", path]);
    let routes = second.routes();
    assert_eq!(taking(&routes, "MON 3 video").as_deref(), Some("CAM 3 video"));
    assert_eq!(taking(&routes, "MON 1 video"), None);
    assert_eq!(taking(&routes, "MON 2 video").as_deref(), Some("CAM 2 video"));
    let log = second.get("/api/log")["log"].clone();
    assert_eq!(log.as_array().unwrap().len(), 2, "{log:#}");
    assert_eq!(log[0]["id"], taken["log_id"]);
    let mut socket = second.events();
    assert_eq!(next(&mut socket, "hello")["log"], log);

    // Without a state file, nothing is kept.
    drop(second);
    let third = Router::start();
    assert_eq!(taking(&third.routes(), "MON 3 video"), None);
    assert_eq!(third.get("/api/log")["log"], json!([]));
}

/// `st2110 send --nmos` and `st2110 receive --nmos` are NMOS Nodes: each registers with
/// the demo registry, `st2110 connect` routes the Receiver, and the demo's own, to the
/// Sender, the stream arrives, and both withdraw when they finish.
#[test]
fn send_and_receive_register_with_the_demo_and_connect_routes_them() {
    let router = Router::start();
    let registry = format!("http://{}", router.address);
    let nmos = format!("--nmos={registry}");
    let st2110 = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_st2110"));
        command.args(args).env("NO_COLOR", "1").env("NO_PROXY", "127.0.0.1").env("no_proxy", "127.0.0.1");
        command
    };
    let sender = st2110(&["send", "audio", "--to", "239.10.60.1:5004", "--interface", "127.0.0.1"])
        .args(["--clock", "traceable", "--duration", "9", "--label", "Test tone", &nmos])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runs");
    let receiver = st2110(&["receive", &nmos, "--media", "audio", "--interface", "127.0.0.1"])
        .args(["--duration", "6", "--label", "Test monitor"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runs");
    let labels = |kind: &str| -> Vec<String> {
        let found = router.get(&format!("/x-nmos/query/v1.3/{kind}/"));
        found.as_array().expect("a list").iter().filter_map(|r| r["label"].as_str().map(String::from)).collect()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(labels("senders").contains(&"Test tone".into()) && labels("receivers").contains(&"Test monitor".into())) {
        assert!(Instant::now() < deadline, "not registered: {:?} {:?}", labels("senders"), labels("receivers"));
        std::thread::sleep(Duration::from_millis(50));
    }
    let tone = router
        .get("/x-nmos/query/v1.3/senders/")
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["label"] == "Test tone")
        .cloned()
        .unwrap();
    assert_eq!(tone["transport"], "urn:x-nmos:transport:rtp.mcast", "{tone:#}");
    let flow = router.get(&format!("/x-nmos/query/v1.3/flows/{}", tone["flow_id"].as_str().unwrap()));
    assert_eq!(flow["format"], "urn:x-nmos:format:audio", "{flow:#}");

    for monitor in ["Test monitor", "MON 4 audio"] {
        let output =
            st2110(&["connect", &registry, "--receiver", monitor, "--sender", "Test tone"]).output().expect("runs");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{text}{}", String::from_utf8_lossy(&output.stderr));
    }
    assert_eq!(taking(&router.routes(), "MON 4 audio").as_deref(), Some("Test tone"));

    // A registry that forgot the Node hears it again at its next heartbeat.
    let node = tone["device_id"].as_str().map(|d| router.get(&format!("/x-nmos/query/v1.3/devices/{d}"))).unwrap();
    let path = format!("/x-nmos/registration/v1.3/resource/nodes/{}", node["node_id"].as_str().unwrap());
    assert_eq!(router.request("DELETE", &path, &[], "").0, 204);
    assert!(!labels("senders").contains(&"Test tone".into()));
    let deadline = Instant::now() + Duration::from_secs(7);
    while !labels("senders").contains(&"Test tone".into()) {
        assert!(Instant::now() < deadline, "not registered again: {:?}", labels("senders"));
        std::thread::sleep(Duration::from_millis(50));
    }

    let sent = sender.wait_with_output().expect("finishes");
    let said = String::from_utf8_lossy(&sent.stderr);
    assert_eq!(sent.status.code(), Some(0), "{said}");
    assert!(said.contains("NMOS: Sender "), "{said}");
    assert!(
        said.contains(&format!("registered it with {registry}/x-nmos/registration/v1.3/, and withdrew it")),
        "{said}"
    );
    let received = receiver.wait_with_output().expect("finishes");
    let (report, said) = (String::from_utf8_lossy(&received.stdout), String::from_utf8_lossy(&received.stderr));
    assert_eq!(received.status.code(), Some(0), "{report}{said}");
    assert!(said.contains("and withdrew it"), "{said}");
    assert!(!labels("senders").contains(&"Test tone".into()), "{:?}", labels("senders"));
    assert!(!labels("receivers").contains(&"Test monitor".into()), "{:?}", labels("receivers"));
}

/// `st2110 receive --nmos` has an IS-12 control endpoint with a BCP-008-01 Receiver
/// monitor: a controller finds it, reads it, and hears it change by subscribing; the
/// router's page hears the same, and `st2110 nmos` shows it.
#[test]
fn a_receivers_status_monitor_says_what_the_stream_does_over_is_12() {
    use st2110_nmos::ncp::{self, client::Connection, property};
    let router = Router::start();
    let registry = format!("http://{}", router.address);
    let nmos = format!("--nmos={registry}");
    let st2110 = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_st2110"));
        command.args(args).env("NO_COLOR", "1").env("NO_PROXY", "127.0.0.1").env("no_proxy", "127.0.0.1");
        command
    };
    let mut receiver = st2110(&["receive", &nmos, "--media", "audio", "--interface", "127.0.0.1"])
        .args(["--duration", "30", "--label", "Watched monitor"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("runs");
    let find = |kind: &str, label: &str| -> Option<Value> {
        let found = router.get(&format!("/x-nmos/query/v1.3/{kind}/"));
        found.as_array()?.iter().find(|r| r["label"] == label).cloned()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let watched = loop {
        if let Some(found) = find("receivers", "Watched monitor") {
            break found;
        }
        assert!(Instant::now() < deadline, "not registered");
        std::thread::sleep(Duration::from_millis(50));
    };
    let id = watched["id"].as_str().unwrap().to_string();
    let device = router.get(&format!("/x-nmos/query/v1.3/devices/{}", watched["device_id"].as_str().unwrap()));
    let control = device["controls"].as_array().unwrap().iter().find(|c| c["type"] == ncp::CONTROL_TYPE).cloned();
    let href = control.expect("an IS-12 control")["href"].as_str().unwrap().to_string();

    // Found by class, read with Get, and subscribed to.
    let mut controller = Connection::open(&href, &[], Duration::from_secs(5)).expect("connects");
    let monitors = controller.monitors().expect("reads its monitors");
    assert_eq!(monitors.len(), 1, "{monitors:?}");
    let monitor = &monitors[0];
    assert_eq!(monitor["classId"], json!([1, 2, 2, 1]), "{monitor:#}");
    assert_eq!(monitor["touchpoints"][0]["resource"], json!({"resourceType": "receiver", "id": id}));
    assert_eq!(monitor["properties"]["overallStatus"], 0, "inactive until connected: {monitor:#}");
    assert_eq!(monitor["properties"]["statusReportingDelay"], 3, "{monitor:#}");
    let oid = monitor["oid"].as_u64().unwrap();
    let delay = json!({"id": property::STATUS_REPORTING_DELAY.json(), "value": 1});
    controller.call(oid, ncp::method::SET, delay).expect("sets the delay");
    assert_eq!(controller.subscribe(&[oid]).expect("subscribes"), [oid]);
    controller.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut page = router.events();
    let mut overall = |want: u64, within: Duration| {
        let deadline = Instant::now() + within;
        let mut heard = Vec::new();
        while Instant::now() < deadline {
            match controller.next_change() {
                Ok(Some(change)) if change.property == property::OVERALL_STATUS => {
                    heard.push(change.value.clone());
                    if change.value == want {
                        return;
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the Device closed the connection"),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => panic!("{e}"),
            }
        }
        panic!("overallStatus never became {want}: heard {heard:?}");
    };

    // Connected to a Sender that sends: healthy at once.
    let mut sender = st2110(&["send", "audio", "--to", "239.10.60.2:5006", "--interface", "127.0.0.1"])
        .args(["--clock", "traceable", "--duration", "30", "--label", "Watched tone", &nmos])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("runs");
    let deadline = Instant::now() + Duration::from_secs(5);
    while find("senders", "Watched tone").is_none() {
        assert!(Instant::now() < deadline, "the sender is not registered");
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = st2110(&["connect", &registry, "--receiver", "Watched monitor", "--sender", "Watched tone"])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    overall(1, Duration::from_secs(5));

    // The Sender stops: nothing arrives, which is unhealthy, at once.
    let _ = sender.kill();
    let _ = sender.wait();
    overall(3, Duration::from_secs(5));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let message = next(&mut page, "monitors");
        let status = &message["monitors"][&id];
        if status["overall"] == "Unhealthy" {
            assert_eq!(status["kind"], "receiver", "{status:#}");
            break;
        }
        assert!(Instant::now() < deadline, "the page never heard it: {message:#}");
    }
    let output = st2110(&["nmos", &registry]).output().expect("runs");
    let text = String::from_utf8_lossy(&output.stdout);
    let after = text.split("Watched monitor").nth(1).unwrap_or_default();
    let line = after.lines().nth(1).unwrap_or_default();
    assert!(line.trim_start().starts_with("monitor: unhealthy"), "{text}");
    controller.close();
    let _ = receiver.kill();
    let _ = receiver.wait();
}
