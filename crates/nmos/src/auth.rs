//! IS-10 authorization, as a client: the access token a registry or a Node asks for, and
//! how to get one.
//!
//! A [`Token`] is given to [`crate::client::Options`] (and to the Connection API client
//! in `st2110-connect`), which then send it in `Authorization: Bearer …` with each
//! request (IS-10 v1.0 Behaviour: Clients, Accessing Protected Resources). It comes
//! from one of four places:
//!
//! - [`Token::fixed`]: one given as it is.
//! - [`Token::file`]: a file holding one, read again whenever it changes, so that
//!   another program can keep it fresh.
//! - [`Token::client_credentials`]: an IS-10 Authorization Server, found from its
//!   RFC 8414 metadata, asked for one with the OAuth 2.0 Client Credentials grant and
//!   the client's id and secret (`client_secret_basic`) or an assertion signed with its
//!   key (`private_key_jwt`, RFC 7523), and asked again when it is half way to
//!   expiring, as IS-10 recommends, or when a server refuses it.
//! - [`Token::sign_in`]: a person, who signs in to the Authorization Server in their
//!   browser, by the Authorization Code grant (RFC 6749 §4.1) with PKCE (RFC 7636,
//!   `S256`): [`Token::begin_sign_in`] gives the address to send the browser to, and
//!   [`Token::finish_sign_in`] swaps the code it comes back with for a token. The
//!   token is renewed with the refresh token the server gives, if it gives one, and
//!   until someone signs in there is none to send.
//!
//! A client that is not registered yet can register itself with [`register`], by OAuth
//! 2.0 Dynamic Client Registration (RFC 7591), as IS-10 recommends for zero
//! configuration: with an initial access token, or unauthenticated where the server
//! allows it. [`SigningKey`] is the key a `private_key_jwt` client signs with, and
//! publishes at its `jwks_uri`.
//!
//! A token is only sent over HTTPS, or to this machine: IS-10 and BCP-003-01 expect TLS,
//! and a token sent in the clear can be read by anyone on the way.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use ureq::Agent;

/// The scopes `st2110 router`, `st2110 connect` and the other controllers ask for, one
/// for each API, as IS-10 has it: reading the registry (IS-04 Query API) and a Node peer
/// to peer (Node API), making connections (IS-05), changing Devices' channel maps
/// (IS-08) and reading their status monitors (IS-12).
pub const SCOPES: &str = "query node connection channelmapping ncp";

/// The well-known path of an Authorization Server's metadata (RFC 8414 §3).
const WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";

/// The most a token or metadata response may hold.
const LIMIT: u64 = 1 << 20;

/// How long a sign-in may take, from sending the browser to the Authorization Server
/// to its coming back.
const SIGN_IN_TIME: Duration = Duration::from_secs(300);

/// The most sign-ins begun and not finished that are kept: a page reloaded many times
/// should not fill memory.
const MOST_PENDING: usize = 16;

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

pub(crate) fn error(message: impl Into<String>) -> Error {
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
    /// The key to sign a `private_key_jwt` assertion with, instead of sending the
    /// secret, for a client registered that way.
    pub key: Option<SigningKey>,
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

/// How a person signs in, for a [`Token::sign_in`].
#[derive(Clone)]
pub struct SignIn {
    /// The server's issuer URL, such as `https://auth.example/`, or its metadata URL.
    pub server: String,
    /// The id the client is registered with, for the Authorization Code grant.
    pub client_id: String,
    /// The secret of a confidential client; `None` for a public one, which PKCE alone
    /// protects.
    pub client_secret: Option<String>,
    /// The scopes to ask for, separated by spaces: [`SCOPES`] for a controller.
    pub scope: String,
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn")
            .field("server", &self.server)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// A sign-in begun: the Authorization Server's address to send the browser to, and the
/// `state` that comes back with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorize {
    /// The authorization endpoint, with the request in its query.
    pub url: String,
    /// The `state` sent, which the browser brings back.
    pub state: String,
}

/// Who has signed in, as far as the server says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedIn {
    /// The `sub` of an access token that is a JWT: who it acts for. Read without
    /// checking its signature, so only to show.
    pub subject: Option<String>,
    /// The scopes the server granted, when it says.
    pub scope: Option<String>,
}

/// A sign-in begun and not finished.
struct Pending {
    state: String,
    verifier: String,
    redirect_uri: String,
    begun: Instant,
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
    SignIn { sign_in: SignIn, agent: Agent },
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
    /// With sign-in: its authorization endpoint, once its metadata has been read.
    authorize: Option<String>,
    /// With sign-in: the refresh token, when the server gave one.
    refresh: Option<String>,
    /// With sign-in: who signed in, while signed in.
    signed_in: Option<SignedIn>,
    /// With sign-in: the sign-ins begun and not finished, oldest first.
    pending: Vec<Pending>,
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
        Self::new(Source::Client { credentials, agent: agent(timeout, env_proxy) })
    }

    /// Tokens for whoever signs in, by the Authorization Code grant with PKCE. There is
    /// none until someone has.
    pub fn sign_in(sign_in: SignIn, timeout: Duration, env_proxy: bool) -> Self {
        Self::new(Source::SignIn { sign_in, agent: agent(timeout, env_proxy) })
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
                let by = if credentials.key.is_some() { ", signing with its key" } else { "" };
                format!("tokens for {} from {}{by}", credentials.client_id, credentials.server)
            }
            Source::SignIn { sign_in, .. } => {
                format!("tokens for whoever signs in, as {} at {}", sign_in.client_id, sign_in.server)
            }
        }
    }

    /// Whether its tokens come from a person signing in.
    pub fn signs_in(&self) -> bool {
        matches!(self.inner.source, Source::SignIn { .. })
    }

    /// Who has signed in, while there is a token to send or a refresh token to get one
    /// with; `None` before anyone has, after [`Token::sign_out`], and once the sign-in
    /// has run out.
    pub fn signed_in(&self) -> Option<SignedIn> {
        let held = self.inner.held.lock().ok()?;
        let current = held.value.is_some() && held.expires.is_none_or(|at| Instant::now() < at);
        held.signed_in.clone().filter(|_| current || held.refresh.is_some())
    }

    /// Begins a sign-in: a fresh `state`, and a PKCE verifier kept for it (RFC 7636
    /// §4.1), and the address of the Authorization Server's authorization endpoint
    /// that asks for a code for them, to be sent back to `redirect_uri`.
    pub fn begin_sign_in(&self, redirect_uri: &str) -> Result<Authorize, Error> {
        let Source::SignIn { sign_in, agent } = &self.inner.source else {
            return Err(error("these tokens come from no sign-in"));
        };
        let mut held = self.inner.held.lock().map_err(|_| error("the token store failed"))?;
        let endpoint = match &held.authorize {
            Some(url) => url.clone(),
            None => {
                let (token_endpoint, metadata) = discover(agent, &sign_in.server, "authorization_code")?;
                let url = metadata
                    .get("authorization_endpoint")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error(format!("{}: no authorization_endpoint in its metadata", sign_in.server)))?
                    .to_string();
                // RFC 8414 §2: a server that lists its methods without S256 does not
                // take it, and no sign-in is made without PKCE.
                let methods = metadata.get("code_challenge_methods_supported").and_then(Value::as_array);
                if methods.is_some_and(|m| !m.iter().any(|m| m.as_str() == Some("S256"))) {
                    return Err(error(format!("{}: the server does not take PKCE with S256", sign_in.server)));
                }
                if !may_send_to(&url) {
                    return Err(error(format!("{url}: people sign in over https:// only, or on this machine")));
                }
                held.endpoint = Some(token_endpoint);
                held.authorize = Some(url.clone());
                url
            }
        };
        let state = random_id()?;
        let mut secret = [0u8; 32];
        SystemRandom::new().fill(&mut secret).map_err(|_| error("no random number"))?;
        // 43 characters of the unreserved set, as RFC 7636 §4.1 asks.
        let verifier = base64url(&secret);
        let url = authorize_url(&endpoint, sign_in, redirect_uri, &state, &pkce_challenge(&verifier));
        let now = Instant::now();
        held.pending.retain(|p| now.duration_since(p.begun) < SIGN_IN_TIME);
        let extra = (held.pending.len() + 1).saturating_sub(MOST_PENDING);
        held.pending.drain(..extra);
        held.pending.push(Pending {
            state: state.clone(),
            verifier,
            redirect_uri: redirect_uri.to_string(),
            begun: now,
        });
        Ok(Authorize { url, state })
    }

    /// Finishes the sign-in that `state` began, swapping the `code` the browser came
    /// back with for a token (RFC 6749 §4.1.3), with the PKCE verifier kept for it. A
    /// `state` not begun here, or begun too long ago, is refused, and each is taken
    /// once.
    pub fn finish_sign_in(&self, state: &str, code: &str) -> Result<SignedIn, Error> {
        let Source::SignIn { sign_in, agent } = &self.inner.source else {
            return Err(error("these tokens come from no sign-in"));
        };
        let mut held = self.inner.held.lock().map_err(|_| error("the token store failed"))?;
        let now = Instant::now();
        held.pending.retain(|p| now.duration_since(p.begun) < SIGN_IN_TIME);
        let Some(at) = held.pending.iter().position(|p| p.state == state) else {
            return Err(error("this sign-in was not begun here, or took too long: sign in again"));
        };
        let pending = held.pending.remove(at);
        let endpoint = held.endpoint.clone().ok_or_else(|| error("the server's token endpoint is not known"))?;
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            form_encode(code),
            form_encode(&pending.redirect_uri),
            form_encode(&pending.verifier)
        );
        let reply = post_form(agent, &endpoint, form, &sign_in.client_id, sign_in.client_secret.as_deref())?;
        let (value, lifetime) = access_token(&reply, &endpoint)?;
        let who = SignedIn {
            subject: subject(&value),
            scope: reply.get("scope").and_then(Value::as_str).map(str::to_string),
        };
        keep(&mut held, now, value, lifetime);
        held.refresh = reply.get("refresh_token").and_then(Value::as_str).map(str::to_string);
        held.signed_in = Some(who.clone());
        Ok(who)
    }

    /// Forgets the tokens got by signing in, so that none is sent until someone signs
    /// in again. They are not revoked at the server.
    pub fn sign_out(&self) {
        let Ok(mut held) = self.inner.held.lock() else { return };
        held.value = None;
        held.renew = None;
        held.expires = None;
        held.refresh = None;
        held.signed_in = None;
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
                    Ok((value, lifetime)) => Ok(keep(&mut held, now, value, lifetime)),
                    // One that has not expired yet is still good to send.
                    Err(e) => match held.value.as_ref().filter(|_| held.expires.is_some_and(|at| now < at)) {
                        Some(value) => Ok(value.clone()),
                        None => Err(e),
                    },
                }
            }
            Source::SignIn { sign_in, agent } => {
                if let Some(value) = held.value.as_ref().filter(|_| held.renew.is_none_or(|at| now < at)) {
                    return Ok(value.clone());
                }
                let unexpired = held.value.clone().filter(|_| held.expires.is_some_and(|at| now < at));
                let (Some(refresh), Some(endpoint)) = (held.refresh.clone(), held.endpoint.clone()) else {
                    return unexpired.ok_or_else(|| match held.signed_in {
                        Some(_) => error("the sign-in has run out: sign in again on the router's page"),
                        None => error("no one has signed in: sign in on the router's page"),
                    });
                };
                // RFC 6749 §6, for the scopes first granted.
                let form = format!("grant_type=refresh_token&refresh_token={}", form_encode(&refresh));
                match post_form(agent, &endpoint, form, &sign_in.client_id, sign_in.client_secret.as_deref()) {
                    Ok(reply) => {
                        let (value, lifetime) = access_token(&reply, &endpoint)?;
                        // A server may give a new refresh token, and then the old one is spent.
                        if let Some(next) = reply.get("refresh_token").and_then(Value::as_str) {
                            held.refresh = Some(next.to_string());
                        }
                        if let Some(who) = held.signed_in.as_mut() {
                            who.subject = subject(&value).or(who.subject.take());
                        }
                        Ok(keep(&mut held, now, value, lifetime))
                    }
                    Err(e) => {
                        // A refresh token the server no longer takes ends the sign-in.
                        if e.message.contains("invalid_grant") {
                            held.refresh = None;
                        }
                        unexpired.ok_or(e)
                    }
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
            let (found, _) = discover(agent, &credentials.server, "client_credentials")?;
            *endpoint = Some(found.clone());
            found
        }
    };
    let mut body = format!("grant_type=client_credentials&scope={}", form_encode(&credentials.scope));
    let reply = match &credentials.key {
        // RFC 7523 §2.2: the client authenticates with an assertion it signs, and sends
        // no secret.
        Some(key) => {
            let assertion = key.assertion(&credentials.client_id, &token_endpoint)?;
            body.push_str(&format!(
                "&client_assertion_type={}&client_assertion={assertion}",
                form_encode(ASSERTION_TYPE)
            ));
            post_form(agent, &token_endpoint, body, &credentials.client_id, None)?
        }
        None => post_form(agent, &token_endpoint, body, &credentials.client_id, Some(&credentials.client_secret))?,
    };
    access_token(&reply, &token_endpoint)
}

/// Reads the metadata of the Authorization Server whose issuer or metadata URL is
/// `server`: its token endpoint, which it must give, and the whole of it. A server that
/// lists the grants it offers without `grant` is refused.
fn discover(agent: &Agent, server: &str, grant: &str) -> Result<(String, Value), Error> {
    let url = metadata_url(server)?;
    if !may_send_to(&url) {
        return Err(error(format!("{url}: tokens are asked for over https:// only, or on this machine")));
    }
    let metadata = get_json(agent, &url)?;
    let found = metadata
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| error(format!("{url}: no token_endpoint in the server's metadata")))?
        .to_string();
    let grants = metadata.get("grant_types_supported").and_then(Value::as_array);
    if grants.is_some_and(|g| !g.iter().any(|g| g.as_str() == Some(grant))) {
        return Err(error(format!("{url}: the server does not offer the {grant} grant")));
    }
    Ok((found, metadata))
}

/// Posts a token request to `endpoint` (RFC 6749 §3.2) for the client `client_id`: with
/// its secret by HTTP Basic (`client_secret_basic`), or without one, with its id in the
/// form, as a public client, or one whose form carries an assertion, sends it. The
/// server's answer, when it is HTTP 200.
fn post_form(
    agent: &Agent,
    endpoint: &str,
    mut body: String,
    client_id: &str,
    secret: Option<&str>,
) -> Result<Value, Error> {
    if !may_send_to(endpoint) {
        return Err(error(format!("{endpoint}: secrets are sent over https:// only, or on this machine")));
    }
    let mut post = agent
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");
    match secret {
        Some(secret) => {
            let basic = base64(format!("{}:{}", form_encode(client_id), form_encode(secret)).as_bytes());
            post = post.header("Authorization", format!("Basic {basic}"));
        }
        None => body.push_str(&format!("&client_id={}", form_encode(client_id))),
    }
    let mut response = post.send(body).map_err(|e| error(format!("{endpoint}: {e}")))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|e| error(format!("{endpoint}: reading the response: {e}")))?;
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
        return Err(error(format!("{endpoint}: HTTP {status}{why}")));
    }
    Ok(reply)
}

/// The bearer token in a token endpoint's answer (RFC 6749 §5.1), and how long it lasts.
fn access_token(reply: &Value, endpoint: &str) -> Result<(String, Option<Duration>), Error> {
    let value = reply
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && !t.contains(char::is_whitespace))
        .ok_or_else(|| error(format!("{endpoint}: no access_token in the response")))?;
    let kind = reply.get("token_type").and_then(Value::as_str).unwrap_or_default();
    if !kind.eq_ignore_ascii_case("bearer") {
        return Err(error(format!("{endpoint}: a {kind:?} token, not a bearer token")));
    }
    let lifetime = reply.get("expires_in").and_then(Value::as_f64).filter(|s| *s > 0.0).map(Duration::from_secs_f64);
    Ok((value.to_string(), lifetime))
}

/// Keeps a new token, to be renewed half way to expiring, as IS-10 recommends, and at
/// least 15 seconds early.
fn keep(held: &mut Held, now: Instant, value: String, lifetime: Option<Duration>) -> String {
    held.renew = lifetime.map(|l| now + (l / 2).min(l.saturating_sub(Duration::from_secs(15))));
    held.expires = lifetime.map(|l| now + l);
    held.value = Some(value.clone());
    value
}

/// The PKCE `code_challenge` for a verifier by the `S256` method (RFC 7636 §4.2): the
/// base64url of its SHA-256.
pub fn pkce_challenge(verifier: &str) -> String {
    base64url(digest(&SHA256, verifier.as_bytes()).as_ref())
}

/// The address that asks the authorization endpoint for a code (RFC 6749 §4.1.1, RFC
/// 7636 §4.3), keeping any query the endpoint has of its own (RFC 6749 §3.1).
fn authorize_url(endpoint: &str, sign_in: &SignIn, redirect_uri: &str, state: &str, challenge: &str) -> String {
    let join = if endpoint.contains('?') { '&' } else { '?' };
    format!(
        "{endpoint}{join}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        form_encode(&sign_in.client_id),
        form_encode(redirect_uri),
        form_encode(&sign_in.scope),
        form_encode(state),
        form_encode(challenge)
    )
}

/// The `sub` of an access token that is a JWT, read without checking it.
fn subject(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (Some(_), Some(claims), Some(_), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let claims: Value = serde_json::from_slice(&base64url_decode(claims)?).ok()?;
    claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The agent every request to an Authorization Server is made with: no redirects, the
/// certificate authorities [`crate::tls`] trusts, and `timeout` for each request.
pub(crate) fn agent(timeout: Duration, env_proxy: bool) -> Agent {
    let proxy = if env_proxy { ureq::Proxy::try_from_env() } else { None };
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(proxy)
        .tls_config(crate::tls::tls_config())
        .user_agent(concat!("st2110-nmos/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// An Authorization Server's metadata (RFC 8414), from its issuer URL or its metadata
/// URL.
pub fn metadata(server: &str, timeout: Duration, env_proxy: bool) -> Result<Value, Error> {
    let url = metadata_url(server)?;
    get_json(&agent(timeout, env_proxy), &url)
}

/// A client's published keys, from its `jwks_uri`, as an Authorization Server reads
/// them to check its assertions.
pub fn get_jwks(url: &str, timeout: Duration) -> Result<Value, Error> {
    get_json(&agent(timeout, false), url)
}

/// Sixteen random bytes in base64url: for a token, an assertion's `jti` or a name that
/// no one can guess.
pub fn random_id() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).map_err(|_| error("no random number"))?;
    Ok(base64url(&bytes))
}

/// RFC 7523's `client_assertion_type` for a signed JWT.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How a client registers: what it asks to be, and how it will authenticate.
#[derive(Clone, Debug)]
pub struct Registration {
    /// Its name, which IS-10 asks to be unique to each instance of the software.
    pub client_name: String,
    /// The scopes it will ask for, separated by spaces.
    pub scope: String,
    /// Where it publishes the public key of its [`SigningKey`], to register for
    /// `private_key_jwt`; `None` registers for a secret (`client_secret_basic`).
    pub jwks_uri: Option<String>,
    /// The initial access token the server gave for registering (RFC 7591 §3), when it
    /// asks for one.
    pub initial_token: Option<String>,
}

/// What the server registered.
#[derive(Clone, PartialEq, Eq)]
pub struct Registered {
    /// The client id it issued.
    pub client_id: String,
    /// The secret it issued, for a client registered for one.
    pub client_secret: Option<String>,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").field("client_id", &self.client_id).finish_non_exhaustive()
    }
}

/// Registers a client with the Authorization Server whose issuer or metadata URL is
/// `server`, at the `registration_endpoint` its metadata gives (RFC 7591 §3), for the
/// Client Credentials grant (IS-10 Behaviour: Clients, Client Registration).
pub fn register(
    server: &str,
    registration: &Registration,
    timeout: Duration,
    env_proxy: bool,
) -> Result<Registered, Error> {
    let agent = agent(timeout, env_proxy);
    let url = metadata_url(server)?;
    if !may_send_to(&url) {
        return Err(error(format!("{url}: clients register over https:// only, or on this machine")));
    }
    let metadata = get_json(&agent, &url)?;
    let endpoint = metadata
        .get("registration_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| error(format!("{url}: the server offers no dynamic client registration")))?;
    if !may_send_to(endpoint) {
        return Err(error(format!("{endpoint}: clients register over https:// only, or on this machine")));
    }
    let method = if registration.jwks_uri.is_some() { "private_key_jwt" } else { "client_secret_basic" };
    let methods = metadata.get("token_endpoint_auth_methods_supported").and_then(Value::as_array);
    if methods.is_some_and(|m| !m.iter().any(|m| m.as_str() == Some(method))) {
        return Err(error(format!("{url}: the server does not take {method} at its token endpoint")));
    }
    let mut body = json!({
        "client_name": registration.client_name,
        "scope": registration.scope,
        "grant_types": ["client_credentials"],
        "response_types": [],
        "token_endpoint_auth_method": method,
    });
    if let Some(jwks_uri) = &registration.jwks_uri {
        body["jwks_uri"] = json!(jwks_uri);
        body["token_endpoint_auth_signing_alg"] = json!("ES256");
    }
    let mut post = agent.post(endpoint).header("Content-Type", "application/json").header("Accept", "application/json");
    if let Some(token) = &registration.initial_token {
        post = post.header("Authorization", format!("Bearer {token}"));
    }
    let mut response = post.send(body.to_string()).map_err(|e| error(format!("{endpoint}: {e}")))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|e| error(format!("{endpoint}: reading the response: {e}")))?;
    let reply: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        // RFC 7591 §3.2.2: `error`, and perhaps `error_description`.
        let why = [reply.get("error"), reply.get("error_description")]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(": ");
        let why = if why.is_empty() { String::new() } else { format!(": {why}") };
        return Err(error(format!("{endpoint}: HTTP {status}{why}")));
    }
    let client_id = reply
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| error(format!("{endpoint}: no client_id in the response")))?;
    let client_secret = reply.get("client_secret").and_then(Value::as_str).map(str::to_string);
    if registration.jwks_uri.is_none() && client_secret.is_none() {
        return Err(error(format!("{endpoint}: no client_secret in the response")));
    }
    Ok(Registered { client_id: client_id.to_string(), client_secret })
}

/// An ES256 (ECDSA P-256) key a `private_key_jwt` client signs its assertions with.
/// Clones share it.
#[derive(Clone)]
pub struct SigningKey {
    pair: Arc<EcdsaKeyPair>,
    pkcs8: Arc<Vec<u8>>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").field("kid", &self.kid()).finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A new key.
    pub fn generate() -> Result<Self, Error> {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| error("no key could be made"))?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// The key kept as PKCS #8 bytes.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &SystemRandom::new())
            .map_err(|_| error("not an ECDSA P-256 key"))?;
        Ok(Self { pair: Arc::new(pair), pkcs8: Arc::new(pkcs8.to_vec()) })
    }

    /// The key as PKCS #8 bytes, to keep.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public key as a JSON Web Key Set (RFC 7517), to publish at `jwks_uri`.
    pub fn jwks(&self) -> Value {
        let point = self.pair.public_key().as_ref();
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": self.kid(),
            "x": base64url(&point[1..33]), "y": base64url(&point[33..65]),
        }]})
    }

    /// The key's id: the start of its public key, which is enough to tell keys apart.
    pub fn kid(&self) -> String {
        base64url(&self.pair.public_key().as_ref()[1..13])
    }

    /// A client assertion for the token endpoint `audience` (RFC 7523 §3), good for a
    /// minute.
    pub fn assertion(&self, client_id: &str, audience: &str) -> Result<String, Error> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        self.sign(&json!({
            "iss": client_id, "sub": client_id, "aud": audience,
            "iat": now, "exp": now + 60, "jti": random_id()?,
        }))
    }

    /// A JWT of `claims`, signed with ES256 (RFC 7515), its header naming the key's
    /// `kid`: an assertion, or an access token from an Authorization Server that signs
    /// with this key.
    pub fn sign(&self, claims: &Value) -> Result<String, Error> {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": self.kid()});
        let signed =
            format!("{}.{}", base64url(header.to_string().as_bytes()), base64url(claims.to_string().as_bytes()));
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| error("the JWT could not be signed"))?;
        Ok(format!("{signed}.{}", base64url(signature.as_ref())))
    }
}

/// Checks a client assertion as an Authorization Server does (RFC 7523 §3): signed
/// with ES256 by a key in `jwks`, issued by and for `client_id`, for `audience`, and
/// not expired. Gives its `jti`, for the server to refuse a second use.
pub fn verify_assertion(assertion: &str, jwks: &Value, client_id: &str, audience: &str) -> Result<String, Error> {
    let mut parts = assertion.split('.');
    let (Some(header), Some(claims), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(error("the assertion is not a signed JWT"));
    };
    let decode = |part: &str| base64url_decode(part).ok_or_else(|| error("the assertion is not base64url"));
    let header: Value =
        serde_json::from_slice(&decode(header)?).map_err(|_| error("the assertion's header is not JSON"))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(error("the assertion is not signed with ES256"));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let keys = jwks.get("keys").and_then(Value::as_array).into_iter().flatten();
    let signed = &assertion[..assertion.len() - signature.len() - 1];
    let signature = decode(signature)?;
    let verified = keys.filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid).any(|k| {
        let coordinate = |name: &str| k.get(name).and_then(Value::as_str).and_then(base64url_decode);
        let (Some(x), Some(y)) = (coordinate("x"), coordinate("y")) else { return false };
        let point = [&[4u8][..], &x, &y].concat();
        ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(signed.as_bytes(), &signature)
            .is_ok()
    });
    if !verified {
        return Err(error("the assertion is not signed by the client's key"));
    }
    let claims: Value =
        serde_json::from_slice(&decode(claims)?).map_err(|_| error("the assertion's claims are not JSON"))?;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(client_id) || text("sub") != Some(client_id) {
        return Err(error("the assertion is not the client's own"));
    }
    let audience_matches = match claims.get("aud") {
        Some(Value::String(aud)) => aud == audience,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    };
    if !audience_matches {
        return Err(error(format!("the assertion is not for {audience}")));
    }
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if claims.get("exp").and_then(Value::as_u64).is_none_or(|exp| exp < now) {
        return Err(error("the assertion has expired"));
    }
    text("jti").map(str::to_string).ok_or_else(|| error("the assertion has no jti"))
}

fn get_json(agent: &Agent, url: &str) -> Result<Value, Error> {
    get_json_of(agent, url, "Authorization Server metadata")
}

/// The JSON at `url`, which should be `what`.
pub(crate) fn get_json_of(agent: &Agent, url: &str, what: &str) -> Result<Value, Error> {
    let mut response =
        agent.get(url).header("Accept", "application/json").call().map_err(|e| error(format!("{url}: {e}")))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(error(format!("{url}: HTTP {status}: no {what} here")));
    }
    let text = response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string()
        .map_err(|e| error(format!("{url}: reading the response: {e}")))?;
    serde_json::from_str(&text).map_err(|e| error(format!("{url}: expected {what}: {e}")))
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

/// Base64url (RFC 4648 §5), unpadded, as JSON Web Tokens and Keys use it.
pub fn base64url(bytes: &[u8]) -> String {
    base64(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

/// Decodes base64url, padded or not.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.contains(['+', '/']) {
        return None;
    }
    base64_decode(&text.replace('-', "+").replace('_', "/"))
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

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn encodes_base64url() {
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
        assert_eq!(base64url_decode("-_8").as_deref(), Some(&b"\xfb\xff"[..]));
        assert_eq!(base64url_decode("+/8"), None);
    }

    #[test]
    fn signs_assertions_that_its_published_key_verifies() {
        let key = SigningKey::generate().unwrap();
        let again = SigningKey::from_pkcs8(key.pkcs8()).unwrap();
        assert_eq!(key.kid(), again.kid());
        let jwks = key.jwks();
        assert_eq!(jwks["keys"][0]["crv"], "P-256");
        let token = "https://auth.example/token";
        let assertion = again.assertion("client-1", token).unwrap();
        assert!(verify_assertion(&assertion, &jwks, "client-1", token).is_ok());
        assert!(verify_assertion(&assertion, &jwks, "client-2", token).is_err(), "another client's");
        assert!(verify_assertion(&assertion, &jwks, "client-1", "https://elsewhere/").is_err(), "for elsewhere");
        let other = SigningKey::generate().unwrap().jwks();
        assert!(verify_assertion(&assertion, &other, "client-1", token).is_err(), "another key");
        let mut tampered = assertion.clone();
        tampered.insert(assertion.find('.').unwrap() + 2, 'A');
        assert!(verify_assertion(&tampered, &jwks, "client-1", token).is_err(), "tampered");
    }
}

#[cfg(test)]
mod sign_in_tests {
    use super::*;

    fn sign_in() -> SignIn {
        SignIn {
            server: "https://auth.example/".into(),
            client_id: "st2110 router".into(),
            client_secret: None,
            scope: SCOPES.into(),
        }
    }

    #[test]
    fn makes_the_s256_challenge() {
        // RFC 7636 Appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn asks_the_authorization_endpoint_for_a_code() {
        let url = authorize_url(
            "https://auth.example/authorize",
            &sign_in(),
            "http://127.0.0.1:8110/auth/callback",
            "abc",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
        assert_eq!(
            url,
            "https://auth.example/authorize?response_type=code&client_id=st2110+router\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A8110%2Fauth%2Fcallback&scope=query+node+connection+channelmapping+ncp&state=abc\
             &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
        );
        // An endpoint's own query is kept.
        let url = authorize_url("https://auth.example/a?tenant=1", &sign_in(), "http://localhost/cb", "s", "c");
        assert!(url.starts_with("https://auth.example/a?tenant=1&response_type=code&"), "{url}");
    }

    #[test]
    fn has_no_token_until_someone_signs_in() {
        let token = Token::sign_in(sign_in(), Duration::from_secs(1), false);
        assert!(token.signs_in());
        assert_eq!(token.signed_in(), None);
        assert!(token.bearer().unwrap_err().message.contains("sign in"));
        assert!(token.finish_sign_in("never-begun", "code").is_err());
        assert!(token.renewable());
        assert!(!Token::fixed("t").signs_in());
    }

    #[test]
    fn reads_who_a_jwt_is_for() {
        let claims = base64url(br#"{"sub":"colm","scope":"query"}"#);
        assert_eq!(subject(&format!("e30.{claims}.sig")).as_deref(), Some("colm"));
        assert_eq!(subject("opaque"), None);
        assert_eq!(subject("a.b.c.d"), None);
    }
}
