//! IS-10 authorization, as a Resource Server: whether the access token a client sends
//! lets it make the request it makes (IS-10 v1.0.1 Behaviour: Resource Servers, and
//! BCP-003-02).
//!
//! A token is a JWT the Authorization Server signed (RFC 7519). A [`Verifier`] reads
//! the server's RFC 8414 metadata, for its `issuer` and its `jwks_uri`, and the keys
//! there, which it keeps and reads again when a token names a key it does not have, as
//! when the server has a new one. It takes a token that is signed by one of them with
//! RS256, RS384, RS512 or ES256, issued by that server, current give or take
//! [`LEEWAY`], and for an audience (`aud`) that names this host, or a pattern such as
//! `*.studio.example` that does. [`Claims::permits`] then says whether the token's
//! claim for the API, such as `x-nmos-connection`, lets it read or write the path
//! asked for.
//!
//! A request without a token, or with one that is not good, is refused with 401, and
//! one whose token does not reach so far with 403, each with `WWW-Authenticate: Bearer`
//! and an RFC 6750 error ([`Refusal`]).
//!
//! The keys are read over HTTPS, or from this machine: over plain HTTP anyone on the
//! way could put their own in, and then sign any token they liked.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use ring::signature::{
    ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use serde_json::Value;
use ureq::Agent;

use crate::auth::{Error, agent, base64url_decode, error, get_json_of, may_send_to, metadata_url};

/// How far a token's `exp` and `nbf` may be from this machine's clock, for clocks that
/// differ a little.
pub const LEEWAY: Duration = Duration::from_secs(30);

/// The soonest the keys are read again for a token that names a key not among them, so
/// that tokens made up to name keys no one has do not have the server asked each time.
const READ_AGAIN: Duration = Duration::from_secs(5);

/// Why a request is refused (RFC 6750 §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// 401 for a token missing or not good, 403 for one that does not reach so far.
    pub status: u16,
    /// The RFC 6750 error: `invalid_request`, `invalid_token` or `insufficient_scope`.
    pub error: &'static str,
    /// Why, for the client's user.
    pub description: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.description)
    }
}

impl Refusal {
    /// A request with no token.
    pub fn missing() -> Self {
        Self {
            status: 401,
            error: "invalid_request",
            description: "this API asks for an IS-10 access token, in Authorization: Bearer".into(),
        }
    }

    /// A token that is not good: badly made, not signed by the server, run out, or for
    /// another host.
    pub fn invalid(description: impl Into<String>) -> Self {
        Self { status: 401, error: "invalid_token", description: description.into() }
    }

    /// A good token that does not let the client make this request.
    pub fn insufficient(api: &str, write: bool, path: &str) -> Self {
        let what = if write { "write" } else { "read" };
        let path = if path.is_empty() { "the API's root".to_string() } else { path.to_string() };
        Self {
            status: 403,
            error: "insufficient_scope",
            description: format!("the token's x-nmos-{api} claim does not let it {what} {path}"),
        }
    }

    /// The `WWW-Authenticate` header to send with the refusal (RFC 6750 §3), naming the
    /// scope a token needs where it is known.
    pub fn challenge(&self, realm: &str, scope: Option<&str>) -> String {
        // RFC 6750 §3: no quotes or backslashes, and printable ASCII only.
        let clean = |text: &str| -> String {
            text.chars()
                .map(|c| if c == ' ' || (c.is_ascii_graphic() && c != '"' && c != '\\') { c } else { '\'' })
                .collect()
        };
        let mut header = format!(
            "Bearer realm=\"{}\", error=\"{}\", error_description=\"{}\"",
            clean(realm),
            self.error,
            clean(&self.description)
        );
        if let Some(scope) = scope {
            header.push_str(&format!(", scope=\"{}\"", clean(scope)));
        }
        header
    }
}

/// What a token that has been checked says.
#[derive(Clone, Debug, PartialEq)]
pub struct Claims {
    claims: Value,
}

impl Claims {
    /// A claim, by name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }

    /// Who the token acts for (`sub`).
    pub fn subject(&self) -> Option<&str> {
        self.claims.get("sub").and_then(Value::as_str)
    }

    /// When it runs out (`exp`), in seconds since 1970.
    pub fn expires(&self) -> Option<u64> {
        self.claims.get("exp").and_then(Value::as_u64)
    }

    /// Whether it lets its client read, or write, `path` of the API `api` (`node`,
    /// `connection`, `channelmapping`, `ncp` and so on): the path is the request's
    /// below the API's version, such as `single/receivers/<id>/staged`, and is matched
    /// against the `read` or `write` list of the token's `x-nmos-<api>` claim, where
    /// `*` stands for anything (IS-10 v1.0.1 Access Tokens: Private Claims). A token
    /// whose `scope` it gives leaves out the API reaches none of it.
    pub fn permits(&self, api: &str, write: bool, path: &str) -> bool {
        if let Some(scope) = self.claims.get("scope").and_then(Value::as_str)
            && !scope.split_whitespace().any(|s| s == api)
        {
            return false;
        }
        let list = self.claims.get(format!("x-nmos-{api}")).and_then(|c| c.get(if write { "write" } else { "read" }));
        let path = path.trim_matches('/');
        list.and_then(Value::as_array)
            .is_some_and(|paths| paths.iter().filter_map(Value::as_str).any(|p| wildcard(p.trim_matches('/'), path)))
    }
}

/// The API a request's path is for, and the rest of the path below its version: for
/// `/x-nmos/connection/v1.1/single/receivers/`, `connection` and `single/receivers`.
/// `None` for the paths above an API's version, such as `/x-nmos/`, which list what is
/// served and need no token.
pub fn api_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/x-nmos/")?;
    let (api, rest) = rest.split_once('/')?;
    let rest = rest.trim_start_matches('/');
    let (version, below) = rest.split_once('/').unwrap_or((rest, ""));
    (!api.is_empty() && !version.is_empty()).then_some((api, below.trim_matches('/')))
}

/// Whether a request with this method writes, as IS-10 has `write` cover it, rather than
/// reads.
pub fn writes(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// Whether `text` matches `pattern`, where `*` stands for any run of characters.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and where in `text` it is taken to end now.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((at, from)) = star {
            p = at + 1;
            t = from + 1;
            star = Some((at, from + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

/// Whether a token's audience names one of `names`, this host's: its `aud`, a string or
/// a list, each a name or a pattern such as `*.studio.example` (IS-10 v1.0.1 Access
/// Tokens: aud).
fn for_audience(aud: Option<&Value>, names: &[String]) -> bool {
    let patterns: Vec<&str> = match aud {
        Some(Value::String(one)) => vec![one],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => return false,
    };
    patterns.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        names.iter().any(|name| wildcard(&pattern, &name.to_ascii_lowercase()))
    })
}

/// Why a signature was not taken.
enum Unsigned {
    /// The token is not a signed JWT.
    Malformed(&'static str),
    /// None of the keys is the one it names, or one for its algorithm.
    NoKey,
    /// A key it names did not verify it.
    Wrong,
}

/// A JWT's claims, when its signature verifies with one of `jwks`' keys.
fn verify(token: &str, jwks: &Value) -> Result<Value, Unsigned> {
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Unsigned::Malformed("the token is not a signed JWT"));
    };
    let decode = |part: &str| base64url_decode(part).ok_or(Unsigned::Malformed("the token is not base64url"));
    let header: Value =
        serde_json::from_slice(&decode(header)?).map_err(|_| Unsigned::Malformed("the token's header is not JSON"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
    if !matches!(alg, "RS256" | "RS384" | "RS512" | "ES256") {
        return Err(Unsigned::Malformed("the token is not signed with RS256, RS384, RS512 or ES256"));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let signed = &token[..token.len() - signature.len() - 1];
    let signature = decode(signature)?;
    let candidates: Vec<&Value> = jwks
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid)
        .filter(|k| k.get("use").and_then(Value::as_str).is_none_or(|u| u == "sig"))
        .filter(|k| k.get("alg").and_then(Value::as_str).is_none_or(|a| a == alg))
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some(if alg == "ES256" { "EC" } else { "RSA" }))
        .collect();
    if candidates.is_empty() {
        return Err(Unsigned::NoKey);
    }
    let field = |key: &Value, name: &str| key.get(name).and_then(Value::as_str).and_then(base64url_decode);
    let verified = candidates.iter().any(|key| match alg {
        "ES256" => {
            let (Some(x), Some(y)) = (field(key, "x"), field(key, "y")) else { return false };
            if key.get("crv").and_then(Value::as_str) != Some("P-256") {
                return false;
            }
            let point = [&[4u8][..], &x, &y].concat();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point).verify(signed.as_bytes(), &signature).is_ok()
        }
        _ => {
            let (Some(n), Some(e)) = (field(key, "n"), field(key, "e")) else { return false };
            let params = match alg {
                "RS256" => &RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &RSA_PKCS1_2048_8192_SHA384,
                _ => &RSA_PKCS1_2048_8192_SHA512,
            };
            // Big-endian, without the leading zeros some encoders leave in.
            let trim = |bytes: &[u8]| bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..].to_vec();
            RsaPublicKeyComponents { n: trim(&n), e: trim(&e) }.verify(params, signed.as_bytes(), &signature).is_ok()
        }
    });
    if !verified {
        return Err(Unsigned::Wrong);
    }
    serde_json::from_slice(&decode(claims)?).map_err(|_| Unsigned::Malformed("the token's claims are not JSON"))
}

/// A token's claims, when its signature verifies with one of `jwks`' keys (RFC 7515
/// §5.2), as an Authorization Server that holds its own keys checks the tokens it
/// issued.
pub fn verify_signature(token: &str, jwks: &Value) -> Result<Value, Refusal> {
    refused_unless_signed(verify(token, jwks))
}

fn refused_unless_signed(verified: Result<Value, Unsigned>) -> Result<Value, Refusal> {
    verified.map_err(|why| match why {
        Unsigned::Malformed(why) => Refusal::invalid(why),
        Unsigned::NoKey => Refusal::invalid("the token is not signed with a key of the Authorization Server's"),
        Unsigned::Wrong => Refusal::invalid("the token's signature does not verify"),
    })
}

/// Checks a token's claims (RFC 7519 §4.1, IS-10 v1.0.1 Access Tokens): issued by
/// `issuer`, current at `now` (seconds since 1970) give or take [`LEEWAY`], and for an
/// audience among `names`.
pub fn check_claims(claims: Value, issuer: &str, names: &[String], now: u64) -> Result<Claims, Refusal> {
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(Refusal::invalid(format!("the token was not issued by {issuer}")));
    }
    let leeway = LEEWAY.as_secs();
    match claims.get("exp").and_then(Value::as_u64) {
        Some(exp) if exp.saturating_add(leeway) >= now => {}
        Some(_) => return Err(Refusal::invalid("the token has run out")),
        None => return Err(Refusal::invalid("the token has no exp")),
    }
    if claims.get("nbf").and_then(Value::as_u64).is_some_and(|nbf| nbf > now.saturating_add(leeway)) {
        return Err(Refusal::invalid("the token is not good yet"));
    }
    if !for_audience(claims.get("aud"), names) {
        return Err(Refusal::invalid(format!("the token's aud does not name {}", names.join(" or "))));
    }
    Ok(Claims { claims })
}

/// Seconds since 1970, now.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What a [`Verifier`] has read of the Authorization Server.
#[derive(Default)]
struct Keys {
    issuer: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<Value>,
    read: Option<Instant>,
}

/// Checks the tokens sent to a Resource Server against an Authorization Server's keys.
pub struct Verifier {
    server: String,
    names: Vec<String>,
    agent: Agent,
    keys: Mutex<Keys>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier").field("server", &self.server).field("names", &self.names).finish_non_exhaustive()
    }
}

impl Verifier {
    /// Checks tokens from the Authorization Server whose issuer or metadata URL is
    /// `server`, for a host known by `names`, such as its host name and its address.
    /// Nothing is read from the server until [`Verifier::read_keys`], or the first
    /// token.
    pub fn new(server: &str, names: Vec<String>, timeout: Duration, env_proxy: bool) -> Result<Self, Error> {
        let url = metadata_url(server)?;
        if !may_send_to(&url) {
            return Err(error(format!(
                "{url}: the Authorization Server's keys are read over https:// only, or on this machine"
            )));
        }
        Ok(Self { server: server.to_string(), names, agent: agent(timeout, env_proxy), keys: Mutex::default() })
    }

    /// The Authorization Server, as given.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The names the tokens' audience is to include one of.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Reads the Authorization Server's metadata, when it has not been read, and its
    /// keys.
    pub fn read_keys(&self) -> Result<(), Error> {
        let mut keys = self.keys.lock().map_err(|_| error("the keys failed"))?;
        self.read(&mut keys)
    }

    fn read(&self, keys: &mut Keys) -> Result<(), Error> {
        keys.read = Some(Instant::now());
        let jwks_uri = match &keys.jwks_uri {
            Some(uri) => uri.clone(),
            None => {
                let url = metadata_url(&self.server)?;
                let metadata = get_json_of(&self.agent, &url, "Authorization Server metadata")?;
                let text = |name: &str| metadata.get(name).and_then(Value::as_str).map(str::to_string);
                let issuer =
                    text("issuer").ok_or_else(|| error(format!("{url}: no issuer in the server's metadata")))?;
                let uri =
                    text("jwks_uri").ok_or_else(|| error(format!("{url}: no jwks_uri in the server's metadata")))?;
                if !may_send_to(&uri) {
                    return Err(error(format!(
                        "{uri}: the server's keys are read over https:// only, or on this machine"
                    )));
                }
                keys.issuer = Some(issuer);
                keys.jwks_uri = Some(uri.clone());
                uri
            }
        };
        let jwks = get_json_of(&self.agent, &jwks_uri, "JSON Web Key Set")?;
        if !jwks.get("keys").is_some_and(Value::is_array) {
            return Err(error(format!("{jwks_uri}: not a JSON Web Key Set")));
        }
        keys.jwks = Some(jwks);
        Ok(())
    }

    /// Checks a token: signed by one of the Authorization Server's keys, read again if
    /// it names one not among them, issued by it, current, and for this host. What it
    /// lets the client do is for [`Claims::permits`] to say.
    pub fn check(&self, token: &str) -> Result<Claims, Refusal> {
        let (claims, issuer) = {
            let mut keys = self.keys.lock().map_err(|_| Refusal::invalid("the keys failed"))?;
            let due = |keys: &Keys, after: Duration| keys.read.is_none_or(|at| at.elapsed() >= after);
            if keys.jwks.is_none() && due(&keys, Duration::from_secs(1)) {
                let _ = self.read(&mut keys);
            }
            let Some(jwks) = &keys.jwks else {
                return Err(Refusal::invalid(format!("the keys of {} cannot be read yet", self.server)));
            };
            let claims = match verify(token, jwks) {
                Err(Unsigned::NoKey) if due(&keys, READ_AGAIN) => {
                    // A key it has not read: a new one, perhaps.
                    if let Err(e) = self.read(&mut keys) {
                        return Err(Refusal::invalid(format!("the token names a key that cannot be read: {e}")));
                    }
                    verify_signature(token, keys.jwks.as_ref().unwrap_or(&Value::Null))?
                }
                other => refused_unless_signed(other)?,
            };
            (claims, keys.issuer.clone().unwrap_or_default())
        };
        check_claims(claims, &issuer, &self.names, unix_now())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;
    use crate::auth::SigningKey;

    /// An RSA key's public half, and tokens it signed with RS256 and RS512 for
    /// `*.studio.example`, made with OpenSSL.
    const N: &str = "tT9nAcloDk1zsNnh4J66NhFedFdx6JrwFp1z-RwWwb2uqYlwIjY8GN7pFQbjnPsop9P2-Pia4DYlCMHqxkX1wdFLKUtcluiB6-f5BCIg73gQG-fTqGI1YMp6U1lQh2-zRlgQT1EgRLkyZfZUGndvRP7oUT_DoFKidVdGb1BG902AeMIjkCAk6qXvrxrLnLpxCqQAz2304Jr963GWbkiUJ5f02ZLPHgtwAm4YSV_CvYCDTBEOI4Qfut4VDVdiFsgWFrDa5k2k-DvAIZYga6NST-Nd7nkNaYF-GkcGaEzMDNtavso9jpGMRZGVJQe2FlfIevjqIe5IANk5nmR97mWTnw";
    const RS256: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS8iLCJzdWIiOiJzdDIxMTAgcm91dGVyIiwiYXVkIjpbIiouc3R1ZGlvLmV4YW1wbGUiXSwiY2xpZW50X2lkIjoic3QyMTEwIHJvdXRlciIsInNjb3BlIjoiY29ubmVjdGlvbiIsImV4cCI6MjAwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJuYmYiOjE3MDAwMDAwMDAsIngtbm1vcy1jb25uZWN0aW9uIjp7InJlYWQiOlsiKiJdLCJ3cml0ZSI6WyJzaW5nbGUvcmVjZWl2ZXJzLyoiXX19.FUEpUr_jg42oSrWZk6wJP2HgxAs3tMWDtjfSrJfgdkPztxGlbp5o7-QdkBTPYau4MiFiRTzPBl9duAuEGP3uSMeecvGKHXpR0TE7rXEIPsBG9SZ4vhz-yB8mBIfKIJvsPb-Ev9-RMGmzvmp47qSot6THyO5VI5WwIw5DznfQII1pn6K2-sY5Sq_XK9pY_uOxMGxRSVNNPCM2S5BrmqXNInAnRj5dbh5CwFiOk5cqlCU3CxSTEvw39vnKGUOPs_h33p47ScOMjJSpJlPPmbunWA8zvDvzCMgDldzOrX3SVMW3ntchXAc3p4ao4x5PdcZDoxJYHmme1fOaGUoM2cL3tQ";
    const RS512: &str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS8iLCJzdWIiOiJzdDIxMTAgcm91dGVyIiwiYXVkIjpbIiouc3R1ZGlvLmV4YW1wbGUiXSwiY2xpZW50X2lkIjoic3QyMTEwIHJvdXRlciIsInNjb3BlIjoiY29ubmVjdGlvbiIsImV4cCI6MjAwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJuYmYiOjE3MDAwMDAwMDAsIngtbm1vcy1jb25uZWN0aW9uIjp7InJlYWQiOlsiKiJdLCJ3cml0ZSI6WyJzaW5nbGUvcmVjZWl2ZXJzLyoiXX19.IxFhvnKZDfFG3dzUMsK_7-eE0Yz1BDdj-JbAnAMDg-NwtsQVMI2x-WzMR4fDPPwgh4hMMaHjsb-vHQRrFOHKRfREv08-fGWSs5-_YYkx5rWrU--VG71O9c3CjEdFEVo1oycXuE9UrbPL8XmqMQpCRIVfFSZCTlh-8asaLUlznMg7nISJ059IbPg785HaCBHUQKBY9oMfFVN3Btf4ChsBMh1Zsbg2j63RsqCY0lktpRhpwEnABXoYNHSwg0Hs7h7vtoEnSX0sOWYaYJkSia52BoT_7bpOt8VJOkr4MgdNpUkLt8BjLaPxMoUxKJNxYz-qT-b1ykobTIR5EdjEisznFw";

    fn rsa_jwks() -> Value {
        json!({"keys": [{"kty": "RSA", "use": "sig", "kid": "test", "n": N, "e": "AQAB"}]})
    }

    fn names() -> Vec<String> {
        vec!["camera-1.studio.example".into(), "192.168.10.21".into()]
    }

    #[test]
    fn verifies_rs256_and_rs512() {
        for token in [RS256, RS512] {
            let claims = verify_signature(token, &rsa_jwks()).unwrap();
            assert_eq!(claims["sub"], "st2110 router");
            let claims = check_claims(claims, "https://auth.example/", &names(), 1_800_000_000).unwrap();
            assert!(claims.permits("connection", false, "single/senders/"));
            assert!(claims.permits("connection", true, "/single/receivers/abc/staged"));
            assert!(!claims.permits("connection", true, "single/senders/abc/staged"), "write reaches receivers only");
            assert!(!claims.permits("node", false, "self"), "no x-nmos-node claim");
        }
        // Tampered with, or checked against another key.
        let mut tampered = RS256.to_string();
        tampered.insert(RS256.find('.').unwrap() + 3, 'A');
        assert_eq!(verify_signature(&tampered, &rsa_jwks()).unwrap_err().status, 401);
        let other = json!({"keys": [{"kty": "RSA", "kid": "test", "n": N.replace('t', "u"), "e": "AQAB"}]});
        assert!(verify_signature(RS256, &other).is_err());
        let elsewhere = json!({"keys": [{"kty": "RSA", "kid": "other", "n": N, "e": "AQAB"}]});
        assert!(verify_signature(RS256, &elsewhere).unwrap_err().description.contains("key"));
        // `alg: none`, or an algorithm the key is not for.
        let none = format!("{}.{}.", crate::auth::base64url(br#"{"alg":"none"}"#), RS256.split('.').nth(1).unwrap());
        assert!(verify_signature(&none, &rsa_jwks()).is_err());
        let es = json!({"keys": [{"kty": "RSA", "kid": "test", "alg": "RS512", "n": N, "e": "AQAB"}]});
        assert!(verify_signature(RS256, &es).is_err());
    }

    #[test]
    fn checks_the_issuer_the_time_and_the_audience() {
        let claims = || verify_signature(RS256, &rsa_jwks()).unwrap();
        let issuer = "https://auth.example/";
        assert!(check_claims(claims(), "https://elsewhere.example/", &names(), 1_800_000_000).is_err());
        assert!(check_claims(claims(), issuer, &names(), 2_000_000_000 + 29).is_ok(), "within the leeway");
        assert!(check_claims(claims(), issuer, &names(), 2_000_000_000 + 31).is_err(), "run out");
        assert!(check_claims(claims(), issuer, &names(), 1_700_000_000 - 29).is_ok(), "within the leeway");
        assert!(check_claims(claims(), issuer, &names(), 1_700_000_000 - 31).is_err(), "not good yet");
        let other = vec!["camera-1.other.example".to_string(), "10.0.0.1".to_string()];
        let refused = check_claims(claims(), issuer, &other, 1_800_000_000).unwrap_err();
        assert_eq!((refused.status, refused.error), (401, "invalid_token"));
    }

    #[test]
    fn matches_wildcards() {
        assert!(wildcard("*", ""));
        assert!(wildcard("*.studio.example", "camera-1.studio.example"));
        assert!(!wildcard("*.studio.example", "studio.example"));
        assert!(wildcard("single/*/staged", "single/receivers/abc/staged"));
        assert!(!wildcard("single/receivers", "single/receivers/abc"));
        assert!(wildcard("a*b*c", "aXbYbZc"));
        assert!(!wildcard("a*b*c", "aXbYbZ"));
        assert!(for_audience(Some(&json!("*")), &names()));
        assert!(for_audience(Some(&json!(["x", "192.168.10.*"])), &names()));
        assert!(for_audience(Some(&json!("CAMERA-1.studio.example")), &names()));
        assert!(!for_audience(None, &names()));
    }

    #[test]
    fn finds_the_api_and_the_path() {
        assert_eq!(api_path("/x-nmos/connection/v1.1/single/receivers/"), Some(("connection", "single/receivers")));
        assert_eq!(api_path("/x-nmos/node/v1.3/"), Some(("node", "")));
        assert_eq!(api_path("/x-nmos/node/v1.3"), Some(("node", "")));
        assert_eq!(api_path("/x-nmos/ncp/v1.0"), Some(("ncp", "")));
        assert_eq!(api_path("/x-nmos/node/"), None);
        assert_eq!(api_path("/x-nmos/"), None);
        assert_eq!(api_path("/"), None);
        assert!(writes("PATCH") && writes("POST") && !writes("GET") && !writes("HEAD"));
    }

    #[test]
    fn verifies_es256_and_reads_the_scope() {
        let key = SigningKey::generate().unwrap();
        let token = key
            .sign(&json!({
                "iss": "https://auth.example/", "sub": "x", "aud": "*", "exp": 2_000_000_000u64,
                "scope": "channelmapping", "x-nmos-channelmapping": {"read": ["*"], "write": ["map/activations"]},
                "x-nmos-node": {"read": ["*"]},
            }))
            .unwrap();
        let claims = verify_signature(&token, &key.jwks()).unwrap();
        let claims = check_claims(claims, "https://auth.example/", &names(), 1_800_000_000).unwrap();
        assert!(claims.permits("channelmapping", true, "map/activations/"));
        assert!(!claims.permits("channelmapping", true, "map/active"));
        assert!(!claims.permits("node", false, "self"), "the scope leaves node out");
        assert!(verify_signature(&token, &SigningKey::generate().unwrap().jwks()).is_err());
    }

    #[test]
    fn says_why_in_a_bearer_challenge() {
        let refusal = Refusal::insufficient("connection", true, "single/receivers/x/staged");
        assert_eq!(refusal.status, 403);
        let header = Refusal::invalid("the \"token\" … ran out").challenge("st2110", Some("connection"));
        assert_eq!(
            header,
            "Bearer realm=\"st2110\", error=\"invalid_token\", error_description=\"the 'token' ' ran out\", scope=\"connection\""
        );
    }

    /// An Authorization Server on this machine that publishes `jwks`, whatever it holds
    /// at the time: gives its issuer, and how many times its metadata and its keys were
    /// read.
    fn authorization_server(jwks: Arc<Mutex<Value>>) -> (String, Arc<[AtomicUsize; 2]>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}/", listener.local_addr().unwrap());
        let reads: Arc<[AtomicUsize; 2]> = Arc::default();
        let (counted, metadata) = (reads.clone(), json!({"issuer": issuer, "jwks_uri": format!("{issuer}jwks")}));
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                    head.push(byte[0]);
                }
                let path = String::from_utf8_lossy(&head).split_whitespace().nth(1).unwrap_or_default().to_string();
                let body = if path.ends_with("/jwks") {
                    counted[1].fetch_add(1, Ordering::SeqCst);
                    jwks.lock().unwrap().to_string()
                } else {
                    counted[0].fetch_add(1, Ordering::SeqCst);
                    metadata.to_string()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (issuer, reads)
    }

    /// The Authorization Server moves to a new key: a token that names it has the keys
    /// read again, but not more often than every [`READ_AGAIN`], however many tokens name
    /// keys it does not have.
    #[test]
    fn reads_the_keys_again_for_a_new_key_at_most_every_five_seconds() {
        let (old, new, unknown) =
            (SigningKey::generate().unwrap(), SigningKey::generate().unwrap(), SigningKey::generate().unwrap());
        let jwks = Arc::new(Mutex::new(old.jwks()));
        let (issuer, reads) = authorization_server(jwks.clone());
        let read = |which: usize| reads[which].load(Ordering::SeqCst);
        let token = |key: &SigningKey| {
            key.sign(
                &json!({"iss": issuer, "sub": "x", "aud": "*", "exp": unix_now() + 60, "x-nmos-node": {"read": ["*"]}}),
            )
            .unwrap()
        };
        let verifier = Verifier::new(&issuer, names(), Duration::from_secs(5), false).unwrap();
        verifier.read_keys().unwrap();
        assert_eq!((read(0), read(1)), (1, 1));
        assert!(verifier.check(&token(&old)).unwrap().permits("node", false, "self"));
        assert_eq!(read(1), 1, "the key it has needs no reading");

        // The server adds a key, and signs with it: the keys were read just now, so a
        // token that names the new one is refused rather than have the server asked.
        let both = json!({"keys": [old.jwks()["keys"][0], new.jwks()["keys"][0]]});
        *jwks.lock().unwrap() = both;
        let refused = verifier.check(&token(&new)).unwrap_err();
        assert_eq!((refused.status, refused.error), (401, "invalid_token"), "{refused}");
        assert_eq!(read(1), 1, "not read again within {READ_AGAIN:?}");

        // Once that long has passed, the token has them read again, and is taken.
        let wind_back = |verifier: &Verifier| {
            let mut keys = verifier.keys.lock().unwrap();
            keys.read = keys.read.and_then(|at| at.checked_sub(READ_AGAIN));
        };
        wind_back(&verifier);
        assert!(verifier.check(&token(&new)).is_ok());
        assert_eq!((read(0), read(1)), (1, 2), "the keys read again, the metadata kept");
        // A key no one has, named just after, is refused without asking again…
        assert!(verifier.check(&token(&unknown)).is_err());
        assert!(verifier.check(&token(&unknown)).is_err());
        assert_eq!(read(1), 2);
        // …and the old key and the new still work.
        assert!(verifier.check(&token(&old)).is_ok() && verifier.check(&token(&new)).is_ok());
        // A key no one has, named after that long, is asked about once more, and refused.
        wind_back(&verifier);
        let refused = verifier.check(&token(&unknown)).unwrap_err();
        assert!(refused.description.contains("key"), "{refused}");
        assert_eq!(read(1), 3);
    }

    #[test]
    fn reads_keys_only_over_tls_or_from_this_machine() {
        assert!(Verifier::new("http://auth.example/", names(), Duration::from_secs(1), false).is_err());
        assert!(Verifier::new("http://127.0.0.1:9/", names(), Duration::from_secs(1), false).is_ok());
        let verifier = Verifier::new("https://127.0.0.1:9/", names(), Duration::from_millis(200), false).unwrap();
        let refused = verifier.check(RS256).unwrap_err();
        assert_eq!(refused.status, 401, "{refused}");
    }
}
