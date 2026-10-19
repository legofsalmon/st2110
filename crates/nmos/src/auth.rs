//! IS-10 authorization, as a client: the access token a registry or a Node asks for, and
//! how to get one.
//!
//! A [`Token`] is given to [`crate::client::Options`] (and to the Connection API client
//! in `st2110-connect`), which then send it in `Authorization: Bearer …` with each
//! request (IS-10 v1.0 Behaviour: Clients, Accessing Protected Resources). It comes
//! from one of three places:
//!
//! - [`Token::fixed`]: one given as it is.
//! - [`Token::file`]: a file holding one, read again whenever it changes, so that
//!   another program can keep it fresh.
//! - [`Token::client_credentials`]: an IS-10 Authorization Server, found from its
//!   RFC 8414 metadata, asked for one with the OAuth 2.0 Client Credentials grant and
//!   the client's id and secret (`client_secret_basic`), and asked again when it is
//!   half way to expiring, as IS-10 recommends, or when a server refuses it.
//!
//! A token is only sent over HTTPS, or to this machine: IS-10 and BCP-003-01 expect TLS,
//! and a token sent in the clear can be read by anyone on the way.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

/// The scopes `st2110 router` and `st2110 connect` ask for: reading the registry and
/// making connections.
pub const SCOPES: &str = "query connection";

/// The well-known path of an Authorization Server's metadata (RFC 8414 §3).
const WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";

/// The most a token or metadata response may hold.
const LIMIT: u64 = 1 << 20;

/// Why no token could be had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// What went wrong, without the token or the secret.
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

fn error(message: impl Into<String>) -> Error {
    Error { message: message.into() }
}

/// How to ask an Authorization Server for a token.
#[derive(Clone)]
pub struct ClientCredentials {
    /// The server's issuer URL, such as `https://auth.example/`, or its metadata URL.
    pub server: String,
    /// The id the client is registered with.
    pub client_id: String,
    /// The secret it was issued.
    pub client_secret: String,
    /// The scopes to ask for, separated by spaces: [`SCOPES`] for a controller.
    pub scope: String,
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("server", &self.server)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// An access token, and how to get the next one. Clones share it.
#[derive(Clone)]
pub struct Token {
    inner: Arc<Inner>,
}

struct Inner {
    source: Source,
    held: Mutex<Held>,
}

enum Source {
    Fixed(String),
    File(PathBuf),
    Client { credentials: ClientCredentials, agent: Agent },
}

#[derive(Default)]
struct Held {
    value: Option<String>,
    /// When to ask for the next one.
    renew: Option<Instant>,
    /// When it stops being any good.
    expires: Option<Instant>,
    /// The file's modification time when it was read.
    modified: Option<SystemTime>,
    /// The Authorization Server's token endpoint, once its metadata has been read.
    endpoint: Option<String>,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(")?;
        f.write_str(&self.describe())?;
        f.write_str(")")
    }
}

impl Token {
    /// A token given as it is.
    pub fn fixed(token: &str) -> Self {
        Self::new(Source::Fixed(token.trim().to_string()))
    }

    /// The token a file holds, read again whenever the file changes.
    pub fn file(path: &Path) -> Result<Self, Error> {
        let token = Self::new(Source::File(path.to_path_buf()));
        token.bearer()?;
        Ok(token)
    }

    /// Tokens from an IS-10 Authorization Server, by the Client Credentials grant.
    /// Nothing is asked of the server until the first token is wanted.
    pub fn client_credentials(credentials: ClientCredentials, timeout: Duration, env_proxy: bool) -> Self {
        let proxy = if env_proxy { ureq::Proxy::try_from_env() } else { None };
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(proxy)
            .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
            .user_agent(concat!("st2110-nmos/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self::new(Source::Client { credentials, agent })
    }

    fn new(source: Source) -> Self {
        Self { inner: Arc::new(Inner { source, held: Mutex::new(Held::default()) }) }
    }

    /// Where the token comes from, in a few words, without the token.
    pub fn describe(&self) -> String {
        match &self.inner.source {
            Source::Fixed(_) => "a token given".into(),
            Source::File(path) => format!("the token in {}", path.display()),
            Source::Client { credentials, .. } => {
                format!("tokens for {} from {}", credentials.client_id, credentials.server)
            }
        }
    }

    /// Whether a refused token can be swapped for another.
    pub fn renewable(&self) -> bool {
        !matches!(self.inner.source, Source::Fixed(_))
    }

    /// The token to send now, getting a new one first when it is due.
    pub fn bearer(&self) -> Result<String, Error> {
        let mut held = self.inner.held.lock().map_err(|_| error("the token store failed"))?;
        let now = Instant::now();
        match &self.inner.source {
            Source::Fixed(token) if token.is_empty() => Err(error("the token given is empty")),
            Source::Fixed(token) => Ok(token.clone()),
            Source::File(path) => {
                let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
                if let Some(value) = held.value.as_ref().filter(|_| held.modified == modified && modified.is_some()) {
                    return Ok(value.clone());
                }
                let text = std::fs::read_to_string(path).map_err(|e| error(format!("{}: {e}", path.display())))?;
                let value = text.trim().strip_prefix("Bearer ").unwrap_or(text.trim()).trim().to_string();
                if value.is_empty() || value.contains(char::is_whitespace) {
                    return Err(error(format!("{} does not hold one token", path.display())));
                }
                held.value = Some(value.clone());
                held.modified = modified;
                Ok(value)
            }
            Source::Client { credentials, agent } => {
                if let Some(value) = held.value.as_ref().filter(|_| held.renew.is_none_or(|at| now < at)) {
                    return Ok(value.clone());
                }
                match request(agent, credentials, &mut held.endpoint) {
                    Ok((value, lifetime)) => {
                        // Half way, as IS-10 recommends, and at least 15 seconds early.
                        held.renew = lifetime.map(|l| now + (l / 2).min(l.saturating_sub(Duration::from_secs(15))));
                        held.expires = lifetime.map(|l| now + l);
                        held.value = Some(value.clone());
                        Ok(value)
                    }
                    // One that has not expired yet is still good to send.
                    Err(e) => match held.value.as_ref().filter(|_| held.expires.is_some_and(|at| now < at)) {
                        Some(value) => Ok(value.clone()),
                        None => Err(e),
                    },
                }
            }
        }
    }

    /// A server refused `token` (HTTP 401): it is not sent again, and the next
    /// [`Token::bearer`] gets another, when there is another to get.
    pub fn refused(&self, token: &str) {
        let Ok(mut held) = self.inner.held.lock() else { return };
        if held.value.as_deref() == Some(token) {
            held.value = None;
            held.renew = None;
            held.expires = None;
            held.modified = None;
        }
    }
}

/// Whether a token may be sent to `url`: over HTTPS (or WSS), or to this machine.
pub fn may_send_to(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if matches!(scheme.to_ascii_lowercase().as_str(), "https" | "wss") {
        return true;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(host, _)| host),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The metadata URL of the Authorization Server whose issuer is `server` (RFC 8414 §3:
/// the well-known path goes between the host and the issuer's own path), or `server`
/// itself when it is a metadata URL already.
pub fn metadata_url(server: &str) -> Result<String, Error> {
    let server = server.trim();
    if server.contains(WELL_KNOWN) {
        return Ok(server.to_string());
    }
    let (scheme, rest) = server
        .split_once("://")
        .filter(|(scheme, _)| matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https"))
        .ok_or_else(|| error(format!("{server} is not an Authorization Server's http:// or https:// URL")))?;
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
    Ok(format!("{scheme}://{authority}{WELL_KNOWN}{}", path.trim_end_matches('/')))
}

/// Asks the Authorization Server for a token: its value, and how long it lasts.
fn request(
    agent: &Agent,
    credentials: &ClientCredentials,
    endpoint: &mut Option<String>,
) -> Result<(String, Option<Duration>), Error> {
    let token_endpoint = match endpoint {
        Some(url) => url.clone(),
        None => {
            let url = metadata_url(&credentials.server)?;
            if !may_send_to(&url) {
                return Err(error(format!("{url}: tokens are asked for over https:// only, or on this machine")));
            }
            let metadata = get_json(agent, &url)?;
            let found = metadata
                .get("token_endpoint")
                .and_then(Value::as_str)
                .ok_or_else(|| error(format!("{url}: no token_endpoint in the server's metadata")))?;
            let grants = metadata.get("grant_types_supported").and_then(Value::as_array);
            if grants.is_some_and(|g| !g.iter().any(|g| g.as_str() == Some("client_credentials"))) {
                return Err(error(format!("{url}: the server does not offer the client_credentials grant")));
            }
            *endpoint = Some(found.to_string());
            found.to_string()
        }
    };
    if !may_send_to(&token_endpoint) {
        return Err(error(format!("{token_endpoint}: secrets are sent over https:// only, or on this machine")));
    }
    let basic = base64(
        format!("{}:{}", form_encode(&credentials.client_id), form_encode(&credentials.client_secret)).as_bytes(),
    );
    let body = format!("grant_type=client_credentials&scope={}", form_encode(&credentials.scope));
    let mut response = agent
        .post(&token_endpoint)
        .header("Authorization", format!("Basic {basic}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .send(body)
        .map_err(|e| error(format!("{token_endpoint}: {e}")))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|e| error(format!("{token_endpoint}: reading the response: {e}")))?;
    let reply: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if status != 200 {
        // RFC 6749 §5.2: `error`, and perhaps `error_description`.
        let why = [reply.get("error"), reply.get("error_description")]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(": ");
        let why = if why.is_empty() { String::new() } else { format!(": {why}") };
        return Err(error(format!("{token_endpoint}: HTTP {status}{why}")));
    }
    let value = reply
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && !t.contains(char::is_whitespace))
        .ok_or_else(|| error(format!("{token_endpoint}: no access_token in the response")))?;
    let kind = reply.get("token_type").and_then(Value::as_str).unwrap_or_default();
    if !kind.eq_ignore_ascii_case("bearer") {
        return Err(error(format!("{token_endpoint}: a {kind:?} token, not a bearer token")));
    }
    let lifetime = reply.get("expires_in").and_then(Value::as_f64).filter(|s| *s > 0.0).map(Duration::from_secs_f64);
    Ok((value.to_string(), lifetime))
}

fn get_json(agent: &Agent, url: &str) -> Result<Value, Error> {
    let mut response =
        agent.get(url).header("Accept", "application/json").call().map_err(|e| error(format!("{url}: {e}")))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(error(format!("{url}: HTTP {status}: no Authorization Server metadata here")));
    }
    let text = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|e| error(format!("{url}: reading the response: {e}")))?;
    serde_json::from_str(&text).map_err(|e| error(format!("{url}: expected the server's metadata: {e}")))
}

/// `application/x-www-form-urlencoded`, as RFC 6749 §2.3.1 encodes a client's id and
/// secret before joining them for HTTP Basic authentication.
pub fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decodes `application/x-www-form-urlencoded` text.
pub fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The client id and secret in an `Authorization: Basic …` header, as a server reads
/// them (RFC 6749 §2.3.1).
pub fn basic_credentials(header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(base64_decode(encoded.trim())?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((form_decode(id), form_decode(secret)))
}

/// The token in an `Authorization: Bearer …` header.
pub fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim()).filter(|t| !t.is_empty())
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 (RFC 4648 §4), padded.
pub(crate) fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0;
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|a| *a == byte)?;
        bits = (bits << 6) | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_base64() {
        for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn reads_basic_and_bearer_headers() {
        let header =
            format!("Basic {}", base64(format!("{}:{}", form_encode("my client"), form_encode("s:e/c")).as_bytes()));
        assert_eq!(basic_credentials(&header), Some(("my client".into(), "s:e/c".into())));
        assert_eq!(basic_credentials("Bearer abc"), None);
        assert_eq!(bearer_token("Bearer abc.def"), Some("abc.def"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
    }

    #[test]
    fn sends_tokens_only_over_tls_or_to_this_machine() {
        for url in [
            "https://registry.example/",
            "wss://r.example/ws",
            "http://127.0.0.1:8110/x",
            "http://localhost/",
            "http://[::1]:80/",
        ] {
            assert!(may_send_to(url), "{url}");
        }
        for url in [
            "http://registry.example/",
            "http://10.0.0.1/",
            "ws://192.168.1.5/ws",
            "http://127.0.0.1.nip.io/",
            "nothing",
        ] {
            assert!(!may_send_to(url), "{url}");
        }
    }

    #[test]
    fn finds_the_metadata() {
        assert_eq!(
            metadata_url("https://auth.example").unwrap(),
            "https://auth.example/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            metadata_url("https://auth.example/x-nmos/auth/v1.0/").unwrap(),
            "https://auth.example/.well-known/oauth-authorization-server/x-nmos/auth/v1.0"
        );
        let given = "https://auth.example/.well-known/oauth-authorization-server";
        assert_eq!(metadata_url(given).unwrap(), given);
        assert!(metadata_url("auth.example").is_err());
    }

    #[test]
    fn reads_a_token_file_again_when_it_changes() {
        let dir = std::env::temp_dir().join(format!("st2110-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "Bearer first\n").unwrap();
        let token = Token::file(&path).unwrap();
        assert_eq!(token.bearer().unwrap(), "first");
        std::fs::write(&path, "second").unwrap();
        // A file system may keep times to the second; a refusal reads it again anyway.
        token.refused("first");
        assert_eq!(token.bearer().unwrap(), "second");
        std::fs::write(&path, "two words").unwrap();
        token.refused("second");
        assert!(token.bearer().is_err());
        assert!(!format!("{token:?}").contains("second"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
