//! The IS-10 options `st2110 nmos`, `st2110 connect` and `st2110 router` share: where
//! the access token comes from, when the registry and the Nodes ask for one.

use std::path::PathBuf;
use std::time::Duration;

use st2110_nmos::auth::{ClientCredentials, SCOPES, Token};

/// The environment variable a client secret can be given in, rather than a file.
const SECRET_VARIABLE: &str = "ST2110_CLIENT_SECRET";

/// Where to get an IS-10 access token. Tokens are sent only over https://, or to this
/// machine.
#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct Auth {
    /// A file holding an IS-10 access token to send, read again whenever it changes, so
    /// that another program can keep it fresh.
    #[arg(long, value_name = "FILE", conflicts_with = "auth")]
    pub token_file: Option<PathBuf>,
    /// An IS-10 Authorization Server to get tokens from, by its issuer URL such as
    /// https://auth.example/: asked with the Client Credentials grant, and again when a
    /// token is half way to expiring. Needs --client-id, and the client's secret in
    /// --client-secret-file or ST2110_CLIENT_SECRET.
    #[arg(long, value_name = "URL", requires = "client_id")]
    pub auth: Option<String>,
    /// The client id registered with the Authorization Server.
    #[arg(long, value_name = "ID", requires = "auth")]
    pub client_id: Option<String>,
    /// A file holding the client's secret, which is kept off the command line, where
    /// other users of this machine could read it.
    #[arg(long, value_name = "FILE", requires = "auth")]
    pub client_secret_file: Option<PathBuf>,
    /// The scopes to ask the Authorization Server for.
    #[arg(long, value_name = "SCOPES", default_value = SCOPES, requires = "auth")]
    pub scope: String,
}

impl Auth {
    /// The token these options name, if any.
    pub(crate) fn token(&self, timeout: Duration, env_proxy: bool) -> Result<Option<Token>, String> {
        if let Some(path) = &self.token_file {
            return Token::file(path).map(Some).map_err(|e| format!("--token-file: {e}"));
        }
        let (Some(server), Some(client_id)) = (&self.auth, &self.client_id) else {
            return Ok(None);
        };
        let client_secret = match &self.client_secret_file {
            Some(path) => std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .map_err(|e| format!("--client-secret-file {}: {e}", path.display()))?,
            None => std::env::var(SECRET_VARIABLE).map_err(|_| {
                format!("--auth needs the client's secret: in --client-secret-file, or in {SECRET_VARIABLE}")
            })?,
        };
        st2110_nmos::auth::metadata_url(server).map_err(|e| format!("--auth: {e}"))?;
        let credentials = ClientCredentials {
            server: server.clone(),
            client_id: client_id.clone(),
            client_secret,
            scope: self.scope.clone(),
        };
        Ok(Some(Token::client_credentials(credentials, timeout, env_proxy)))
    }
}
