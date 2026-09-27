//! An HTTP client for IS-05 v1.0 to v1.2 Connection APIs.
//!
//! ```no_run
//! use st2110_connect::client::{ConnectionClient, Options, single};
//! use st2110_connect::{Activation, Constraints, Plan};
//! use st2110_nmos::Kind;
//!
//! let client = ConnectionClient::new(&Options::default());
//! let api = "http://192.168.10.31/x-nmos/connection/v1.1/";
//! let receiver = "7ecf0001-0000-4000-8000-000000000001";
//! let constraints = client.get(&single(api, Kind::Receiver, receiver, "constraints"))?;
//! let constraints = Constraints::from_json(&constraints.body).expect("IS-05 constraints");
//! let sdp = client.transport_file("http://192.168.10.21/x-nmos/connection/v1.1/single/senders/5e0d0001-0000-4000-8000-000000000001/transportfile")?;
//! let plan = Plan::connect(sdp.body.as_str().unwrap_or_default(), None, &constraints, Activation::Immediate)
//!     .expect("a stream to receive");
//! let reply = client.patch(&single(api, Kind::Receiver, receiver, "staged"), &plan.request)?;
//! if !reply.is_success() {
//!     eprintln!("refused: {}", reply.error());
//! }
//! # Ok::<_, st2110_connect::client::Error>(())
//! ```

use std::fmt;
use std::time::Duration;

use serde_json::Value;
use st2110_nmos::Kind;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::typestate::WithBody;
use ureq::{Agent, RequestBuilder};

/// The most a response may hold: a Receiver's resources, a bulk response, or an SDP file.
const BODY_LIMIT: u64 = 16 << 20;

/// How a [`ConnectionClient`] talks to Connection APIs.
#[derive(Clone, Debug)]
pub struct Options {
    /// How long one request may take, from connecting to the last byte.
    pub timeout: Duration,
    /// Whether to use the proxy that `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` names
    /// (except for hosts in `NO_PROXY`).
    pub env_proxy: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(5), env_proxy: true }
    }
}

/// A request that got no response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The URL that was requested.
    pub url: String,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.url, self.message)
    }
}

impl std::error::Error for Error {}

fn error(url: &str, message: impl Into<String>) -> Error {
    Error { url: url.to_string(), message: message.into() }
}

/// A Connection API's response.
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The body: JSON, or a string when it is not JSON (as an SDP file is not), or
    /// `null` when there is none.
    pub body: Value,
    /// The `Location` header: where a redirect points, or where a `409 Conflict` says
    /// the resource can be changed.
    pub location: Option<String>,
}

impl Reply {
    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// What went wrong, from an IS-05 error response: the status, its `error` and its
    /// `debug` when that adds anything (IS-05 v1.2 error.json).
    pub fn error(&self) -> String {
        let text = |name: &str| self.body.get(name).and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty());
        let error = text("error");
        let debug = text("debug").filter(|d| Some(*d) != error);
        let mut message = format!("HTTP {}", self.status);
        match (error, debug) {
            (Some(e), Some(d)) => message.push_str(&format!(": {e} ({d})")),
            (Some(text), None) | (None, Some(text)) => message.push_str(&format!(": {text}")),
            (None, None) => {}
        }
        if (300..400).contains(&self.status)
            && let Some(location) = &self.location
        {
            message.push_str(&format!(", redirecting to {location}"));
        }
        message
    }
}

/// A client for IS-05 Connection APIs: one can serve every Device in a facility.
#[derive(Clone, Debug)]
pub struct ConnectionClient {
    agent: Agent,
    timeout: Duration,
}

impl ConnectionClient {
    /// A client that makes requests as `options` say.
    pub fn new(options: &Options) -> Self {
        let proxy = if options.env_proxy { ureq::Proxy::try_from_env() } else { None };
        let agent = Agent::config_builder()
            .timeout_global(Some(options.timeout))
            .http_status_as_error(false)
            .proxy(proxy)
            .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
            .user_agent(concat!("st2110-connect/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, timeout: options.timeout }
    }

    /// Reads a resource, such as a Receiver's `/constraints` or `/active`, following
    /// redirects.
    pub fn get(&self, url: &str) -> Result<Reply, Error> {
        let response = self.agent.get(url).header("Accept", "application/json").call();
        read(url, response)
    }

    /// Changes a resource, such as a Receiver's `/staged`. A redirect is returned, not
    /// followed: IS-05 has none for anything but a `GET`, and following it would lose
    /// the request (IS-05 v1.2 APIs: Client Side Implementation Notes).
    pub fn patch(&self, url: &str, body: &Value) -> Result<Reply, Error> {
        self.patch_within(url, body, self.timeout)
    }

    /// Changes a resource as [`ConnectionClient::patch`] does, giving up after `limit`
    /// when that is sooner than the client's timeout.
    pub fn patch_within(&self, url: &str, body: &Value, limit: Duration) -> Result<Reply, Error> {
        self.send(self.agent.patch(url), url, body, limit)
    }

    /// Sends a request, such as a `/bulk/receivers` one. A redirect is returned, not
    /// followed, as for [`ConnectionClient::patch`].
    pub fn post(&self, url: &str, body: &Value) -> Result<Reply, Error> {
        self.post_within(url, body, self.timeout)
    }

    /// Sends a request as [`ConnectionClient::post`] does, giving up after `limit` when
    /// that is sooner than the client's timeout.
    pub fn post_within(&self, url: &str, body: &Value, limit: Duration) -> Result<Reply, Error> {
        self.send(self.agent.post(url), url, body, limit)
    }

    fn send(
        &self,
        request: RequestBuilder<WithBody>,
        url: &str,
        body: &Value,
        limit: Duration,
    ) -> Result<Reply, Error> {
        let request = request.config().max_redirects(0).timeout_global(Some(limit.min(self.timeout))).build();
        let response = request
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send(body.to_string());
        read(url, response)
    }

    /// Fetches a transport file: a Sender's `manifest_href`, or its `/transportfile`,
    /// which may redirect (IS-05 v1.2 Behaviour: Transport Files & Caching). None may
    /// come from a cache, since the file changes when the Sender is reconfigured.
    pub fn transport_file(&self, url: &str) -> Result<Reply, Error> {
        let response = self
            .agent
            .get(url)
            .header("Accept", "application/sdp, text/plain;q=0.9, */*;q=0.8")
            .header("Cache-Control", "no-cache")
            .call();
        read(url, response)
    }
}

fn read(url: &str, response: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Reply, Error> {
    let mut response = response.map_err(|e| error(url, e.to_string()))?;
    let status = response.status().as_u16();
    let location = response.headers().get("Location").and_then(|v| v.to_str().ok()).map(str::to_string);
    let text = response
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .map_err(|e| error(url, format!("reading the response: {e}")))?;
    let body =
        if text.trim().is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::String(text)) };
    Ok(Reply { status, body, location })
}

/// The URL of one of a Sender's or Receiver's resources on a Connection API, such as
/// `…/single/receivers/{id}/staged`. `api` is the versioned base, ending in `/`.
pub fn single(api: &str, kind: Kind, id: &str, resource: &str) -> String {
    format!("{api}single/{}/{id}/{resource}", kind.plural())
}

/// The URL that changes many Senders or Receivers on a Connection API at once:
/// `…/bulk/receivers`, without the trailing slash, as a `POST` must not be redirected.
/// `api` is the versioned base, ending in `/`.
pub fn bulk(api: &str, kind: Kind) -> String {
    format!("{api}bulk/{}", kind.plural())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn errors_say_what_the_api_said() {
        let reply = |status, body: Value, location: Option<&str>| Reply {
            status,
            body,
            location: location.map(str::to_string),
        };
        assert_eq!(
            reply(400, json!({"code": 400, "error": "Invalid JSON", "debug": "destination_port: 70000 > 65535"}), None)
                .error(),
            "HTTP 400: Invalid JSON (destination_port: 70000 > 65535)"
        );
        assert_eq!(
            reply(423, json!({"code": 423, "error": "Locked", "debug": null}), None).error(),
            "HTTP 423: Locked"
        );
        assert_eq!(reply(500, json!({"code": 500, "error": " ", "debug": "boom"}), None).error(), "HTTP 500: boom");
        assert_eq!(reply(404, Value::Null, None).error(), "HTTP 404");
        assert_eq!(
            reply(301, Value::Null, Some("http://mon1/x-nmos/connection/v1.1/single/receivers/r/staged/")).error(),
            "HTTP 301, redirecting to http://mon1/x-nmos/connection/v1.1/single/receivers/r/staged/"
        );
        assert!(reply(202, Value::Null, None).is_success() && !reply(307, Value::Null, None).is_success());
    }

    #[test]
    fn urls_follow_the_api() {
        let api = "http://mon1/x-nmos/connection/v1.1/";
        assert_eq!(
            single(api, Kind::Receiver, "7ecf0001", "staged"),
            "http://mon1/x-nmos/connection/v1.1/single/receivers/7ecf0001/staged"
        );
        assert_eq!(bulk(api, Kind::Receiver), "http://mon1/x-nmos/connection/v1.1/bulk/receivers");
    }
}
