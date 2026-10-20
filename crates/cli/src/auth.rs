//! The IS-10 options `st2110 nmos`, `st2110 connect`, `st2110 router` and `st2110
//! discover` share: where the access token comes from, when the registry and the Nodes
//! ask for one, and where to find a registry or an Authorization Server not named.
//!
//! An Authorization Server not named is found by DNS-SD (`_nmos-auth._tcp`), as IS-10
//! Discovery has clients do. A client not registered yet registers itself by RFC 7591
//! with `--register`, and what the server issues is kept in a file of this user's, so
//! that it registers once, as IS-10 asks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use st2110_nmos::auth::{self, ClientCredentials, Registration, SCOPES, SignIn, SigningKey, Token};

use crate::find::{self, LookArgs};

/// The environment variable a client secret can be given in, rather than a file.
const SECRET_VARIABLE: &str = "ST2110_CLIENT_SECRET";

/// The environment variable an initial access token for registering can be given in.
const REGISTRATION_VARIABLE: &str = "ST2110_REGISTRATION_TOKEN";

/// Where to get an IS-10 access token. Tokens are sent only over https://, or to this
/// machine.
#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct Auth {
    /// A file holding an IS-10 access token to send, read again whenever it changes, so
    /// that another program can keep it fresh.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["auth", "client_id", "register"])]
    pub token_file: Option<PathBuf>,
    /// An IS-10 Authorization Server to get tokens from, by its issuer URL such as
    /// https://auth.example/: asked with the Client Credentials grant, and again when a
    /// token is half way to expiring. Found by DNS-SD (_nmos-auth._tcp) when
    /// --client-id or --register is given without it.
    #[arg(long, value_name = "URL")]
    pub auth: Option<String>,
    /// The client id registered with the Authorization Server, with its secret in
    /// --client-secret-file or ST2110_CLIENT_SECRET.
    #[arg(long, value_name = "ID", conflicts_with = "register")]
    pub client_id: Option<String>,
    /// A file holding the client's secret, which is kept off the command line, where
    /// other users of this machine could read it.
    #[arg(long, value_name = "FILE", requires = "client_id")]
    pub client_secret_file: Option<PathBuf>,
    /// Register with the Authorization Server (RFC 7591 dynamic client registration)
    /// when no registration with it is kept in --client-file, and keep what it issues
    /// there for next time.
    #[arg(long)]
    pub register: bool,
    /// A file holding the initial access token the Authorization Server gave for
    /// registering, when it asks for one; or ST2110_REGISTRATION_TOKEN.
    #[arg(long, value_name = "FILE", requires = "register")]
    pub registration_token_file: Option<PathBuf>,
    /// Where registrations are kept, readable by this user alone; clients.json beside
    /// the router's state file when omitted.
    #[arg(long, value_name = "FILE", requires = "register")]
    pub client_file: Option<PathBuf>,
    /// The scopes to ask the Authorization Server for.
    #[arg(long, value_name = "SCOPES", default_value = SCOPES)]
    pub scope: String,
    #[command(flatten)]
    pub look: LookArgs,
}

/// How a client proves who it is at the token endpoint, when it registers itself.
pub(crate) enum Proof<'a> {
    /// The secret the server issues.
    Secret,
    /// A key whose public half is published at the URL: `private_key_jwt`.
    Key(&'a SigningKey, String),
}

impl Auth {
    /// The token these options name, if any.
    pub(crate) fn token(&self, timeout: Duration, env_proxy: bool) -> Result<Option<Token>, String> {
        self.token_with(timeout, env_proxy, &Proof::Secret)
    }

    /// The token these options name, registering with `proof` when told to register.
    pub(crate) fn token_with(
        &self,
        timeout: Duration,
        env_proxy: bool,
        proof: &Proof,
    ) -> Result<Option<Token>, String> {
        if let Some(path) = &self.token_file {
            return Token::file(path).map(Some).map_err(|e| format!("--token-file: {e}"));
        }
        if self.auth.is_none() && self.client_id.is_none() && !self.register {
            return Ok(None);
        }
        let server = self.server(timeout)?;
        if let Some(client_id) = &self.client_id {
            let client_secret = match &self.client_secret_file {
                Some(path) => std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| format!("--client-secret-file {}: {e}", path.display()))?,
                None => std::env::var(SECRET_VARIABLE).map_err(|_| {
                    format!("--client-id needs the client's secret: in --client-secret-file, or in {SECRET_VARIABLE}")
                })?,
            };
            let credentials = ClientCredentials {
                server,
                client_id: client_id.clone(),
                client_secret,
                scope: self.scope.clone(),
                key: None,
            };
            return Ok(Some(Token::client_credentials(credentials, timeout, env_proxy)));
        }
        if !self.register {
            return Err("--auth needs --client-id, with its secret, or --register".into());
        }
        let store = self.store()?;
        let initial = match &self.registration_token_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| format!("--registration-token-file {}: {e}", path.display()))?,
            ),
            None => std::env::var(REGISTRATION_VARIABLE).ok().filter(|t| !t.trim().is_empty()),
        };
        registered(&server, &self.scope, proof, initial, &store, timeout, env_proxy).map(Some)
    }
}

impl Auth {
    /// The Authorization Server named, or found by DNS-SD.
    fn server(&self, timeout: Duration) -> Result<String, String> {
        match &self.auth {
            Some(server) => {
                auth::metadata_url(server).map_err(|e| format!("--auth: {e}"))?;
                Ok(server.clone())
            }
            None => {
                let servers = find::auth_servers(&self.look, timeout)?;
                let api = &servers[0];
                let issuer = api.issuer();
                eprintln!("Authorization Server: {issuer} ({}, found by {})", api.name, api.by);
                Ok(issuer)
            }
        }
    }

    /// Tokens for whoever signs in on the router's page, as --client-id, with its secret
    /// when it has one.
    pub(crate) fn sign_in(&self, timeout: Duration, env_proxy: bool) -> Result<Token, String> {
        let Some(client_id) = &self.client_id else {
            return Err(
                "--sign-in needs --client-id: the id the Authorization Server registered the router with".into()
            );
        };
        let server = self.server(timeout)?;
        let client_secret = match &self.client_secret_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| format!("--client-secret-file {}: {e}", path.display()))?,
            ),
            None => std::env::var(SECRET_VARIABLE).ok().filter(|s| !s.trim().is_empty()),
        };
        let sign_in = SignIn { server, client_id: client_id.clone(), client_secret, scope: self.scope.clone() };
        Ok(Token::sign_in(sign_in, timeout, env_proxy))
    }

    /// Where registrations are kept.
    fn store(&self) -> Result<PathBuf, String> {
        match &self.client_file {
            Some(path) => Ok(path.clone()),
            None => crate::router::default_state()
                .map(|p| p.with_file_name("clients.json"))
                .ok_or_else(|| "--register needs --client-file, as this machine has no place for it".into()),
        }
    }

    /// The key a client that registers with `private_key_jwt` signs with: the one kept
    /// with the registrations, or a new one, kept there.
    pub(crate) fn kept_key(&self) -> Result<SigningKey, String> {
        let store = self.store()?;
        let mut kept = read_store(&store);
        let saved = kept["key"].as_str().and_then(auth::base64url_decode);
        if let Some(key) = saved.and_then(|pkcs8| SigningKey::from_pkcs8(&pkcs8).ok()) {
            return Ok(key);
        }
        let key = SigningKey::generate().map_err(|e| e.message)?;
        kept["key"] = json!(auth::base64url(key.pkcs8()));
        write_store(&store, &kept).map_err(|e| format!("{}: {e}", store.display()))?;
        Ok(key)
    }
}

/// A token from a registration kept in `store` for `server`, or from a new one. A kept
/// registration the server no longer knows is replaced.
fn registered(
    server: &str,
    scope: &str,
    proof: &Proof,
    initial: Option<String>,
    store: &Path,
    timeout: Duration,
    env_proxy: bool,
) -> Result<Token, String> {
    let signed = matches!(proof, Proof::Key(..));
    let mut kept = read_store(store);
    let entries = kept["registrations"].as_array_mut().expect("an array");
    let matches = |e: &Value| e["issuer"] == server && e["scope"] == scope && e["signed"] == signed;
    if let Some(entry) = entries.iter().find(|e| matches(e)) {
        let token = token_from(server, scope, proof, entry, timeout, env_proxy);
        match token.bearer() {
            Ok(_) => return Ok(token),
            // Forgotten, as the demo's server forgets on a restart: register again.
            Err(e) if e.message.contains("invalid_client") => {}
            Err(e) => return Err(e.message),
        }
    }
    let registration = Registration {
        client_name: client_name(),
        scope: scope.to_string(),
        jwks_uri: match proof {
            Proof::Key(_, uri) => Some(uri.clone()),
            Proof::Secret => None,
        },
        initial_token: initial,
    };
    let issued = auth::register(server, &registration, timeout, env_proxy).map_err(|e| format!("registering: {e}"))?;
    eprintln!("Registered with {server} as {} ({})", issued.client_id, registration.client_name);
    let entry = json!({
        "issuer": server, "scope": scope, "signed": signed,
        "client_name": registration.client_name, "client_id": issued.client_id,
        "client_secret": issued.client_secret,
    });
    let entries = kept["registrations"].as_array_mut().expect("an array");
    entries.retain(|e| !matches(e));
    entries.push(entry.clone());
    if let Err(e) = write_store(store, &kept) {
        eprintln!(
            "st2110: the registration cannot be kept in {}, so the next run registers again: {e}",
            store.display()
        );
    }
    Ok(token_from(server, scope, proof, &entry, timeout, env_proxy))
}

fn token_from(server: &str, scope: &str, proof: &Proof, entry: &Value, timeout: Duration, env_proxy: bool) -> Token {
    let text = |name: &str| entry[name].as_str().unwrap_or_default().to_string();
    let credentials = ClientCredentials {
        server: server.to_string(),
        client_id: text("client_id"),
        client_secret: text("client_secret"),
        scope: scope.to_string(),
        key: match proof {
            Proof::Key(key, _) => Some((*key).clone()),
            Proof::Secret => None,
        },
    };
    Token::client_credentials(credentials, timeout, env_proxy)
}

/// A name unique to this client, as IS-10 asks: the program, this machine, and a
/// random part, since several may run on one machine.
fn client_name() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this machine".into());
    let random = auth::random_id().unwrap_or_else(|_| std::process::id().to_string());
    format!("st2110 {} on {host}, {}", env!("CARGO_PKG_VERSION"), &random[..8.min(random.len())])
}

fn read_store(path: &Path) -> Value {
    let kept = std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok());
    match kept {
        Some(value) if value["registrations"].is_array() => value,
        _ => json!({"registrations": []}),
    }
}

/// Keeps the registrations, readable by this user alone, since they hold secrets.
fn write_store(path: &Path, kept: &Value) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let partial = path.with_extension("json.partial");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&partial)?;
    file.write_all(serde_json::to_string_pretty(kept)?.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&partial, path)
}
