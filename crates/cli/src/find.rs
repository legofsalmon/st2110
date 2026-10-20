//! Finding a registry, or an IS-10 Authorization Server, by DNS-SD when a command is
//! not told where it is: by unicast DNS in the search domains first, then by multicast
//! DNS (`st2110_discover::find`).

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use st2110_discover::find::{self, Look, Seen};
use st2110_discover::nmos::{self, Api, ApiKind};
use st2110_nmos::client::{Options, QueryClient};

/// Where to look for a registry or an Authorization Server that is not named.
#[derive(clap::Args, Clone, Debug, Default)]
pub(crate) struct LookArgs {
    /// A DNS server to ask for a registry or an Authorization Server not named, by
    /// unicast DNS-SD, with its port when it is not 53; those the system uses when
    /// omitted. Give it more than once for several.
    #[arg(long, value_name = "ADDRESS", value_parser = crate::discover::dns_server)]
    pub dns_server: Vec<SocketAddr>,
    /// A domain to look in, such as studio.example; the system's search domains when
    /// omitted. Give it more than once for several.
    #[arg(long, value_name = "DOMAIN")]
    pub domain: Vec<String>,
    /// Where to ask by multicast DNS when unicast DNS-SD finds nothing: its group,
    /// 224.0.0.251:5353, when omitted, or a responder's own address and port.
    #[arg(long, value_name = "ADDRESS:PORT")]
    pub mdns: Option<SocketAddrV4>,
}

impl LookArgs {
    fn look(&self, timeout: Duration) -> Look {
        Look {
            dns_servers: self.dns_server.clone(),
            domains: (!self.domain.is_empty()).then(|| self.domain.clone()),
            mdns: Some(self.mdns.unwrap_or(st2110_discover::MDNS)),
            timeout: timeout.min(Duration::from_secs(5)),
            ..Look::default()
        }
    }
}

/// Where it looked and what got in the way, for a message saying nothing was found.
fn nothing(what: &str, seen: &Seen) -> String {
    let mut message = format!("no {what} named, and none found by DNS-SD");
    if !seen.looked.is_empty() {
        message.push_str(&format!(" ({})", seen.looked.join(", ")));
    }
    for problem in &seen.problems {
        message.push_str(&format!("; {problem}"));
    }
    message.push_str("; name one");
    message
}

/// The Query API URL of the registry a controller would choose, as IS-04's discovery
/// procedure has it: by priority, the next when one does not answer. Says on standard
/// error which one, and how it was found. `authorized` says whether a token can be
/// given, so that a registry asking for one is no worse than one that does not.
pub(crate) fn registry(args: &LookArgs, timeout: Duration, authorized: bool) -> Result<String, String> {
    let seen = find::find(ApiKind::Query, &args.look(timeout));
    let mut order = nmos::by_preference(&seen.apis);
    if authorized {
        // With a token to give, one that asks for authorization is as good as one that
        // does not; the order is otherwise kept.
        order.sort_by_key(|a| {
            let priority = a.priority.unwrap_or(99);
            (priority >= 100, priority)
        });
    }
    if order.is_empty() {
        return Err(nothing("registry", &seen));
    }
    let options = Options { timeout, ..Options::default() };
    let mut problems = Vec::new();
    for api in order {
        // One that asks for a token answers all the same.
        let answered = match QueryClient::connect(&api.url, &options) {
            Ok(_) => Ok(()),
            Err(e) if authorized && (e.message.starts_with("HTTP 401") || e.message.starts_with("HTTP 403")) => Ok(()),
            Err(e) => Err(e),
        };
        match answered {
            Ok(()) => {
                eprintln!("Registry: {} ({}, found by {})", api.url, api.name, api.by);
                return Ok(api.url.clone());
            }
            Err(e) => problems.push(e.to_string()),
        }
    }
    Err(format!("no registry found by DNS-SD answers: {}", problems.join("; ")))
}

/// The IS-10 Authorization Servers found, in the order to try them.
pub(crate) fn auth_servers(args: &LookArgs, timeout: Duration) -> Result<Vec<Api>, String> {
    let seen = find::find(ApiKind::Auth, &args.look(timeout));
    let servers: Vec<Api> = find::by_priority(&seen.apis).into_iter().cloned().collect();
    if servers.is_empty() {
        return Err(nothing("Authorization Server", &seen));
    }
    Ok(servers)
}
