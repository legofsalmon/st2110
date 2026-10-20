//! The demo facility's DNS-SD: a stand-in DNS server, on the router's own address and
//! port over UDP, that advertises the demo registry's Query API (`_nmos-query._tcp`)
//! and Registration API (`_nmos-register._tcp`) and, with `--demo-auth`, its
//! Authorization Server (`_nmos-auth._tcp`), in whatever domain it is asked about,
//! `local` included.
//!
//! So `st2110 nmos --dns-server 127.0.0.1:8110 --domain demo.test` finds the demo by
//! unicast DNS-SD, as IS-04 and IS-10 prefer, and `--mdns 127.0.0.1:8110` by a
//! multicast DNS question sent to it alone, with no network and nothing advertised
//! beyond this machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use st2110_discover::dns::{self, Data, Message, Name, Record};

/// What the demo advertises, at `address`.
pub(crate) struct Advertised {
    pub address: SocketAddr,
    pub auth: bool,
}

/// How long its records may be kept: long enough for one look.
const TTL: u32 = 10;

/// Answers DNS questions on `socket` until the program ends.
pub(crate) fn serve(socket: UdpSocket, advertised: &Advertised) {
    let mut buffer = [0u8; 9000];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buffer) else { continue };
        let Ok(query) = Message::decode(&buffer[..n]) else { continue };
        if query.response {
            continue;
        }
        let response = answer(&query, advertised);
        let _ = socket.send_to(&response.encode(), from);
    }
}

/// The response to `query`: for a browse, the instance with its SRV, TXT and A records
/// alongside, as a multicast DNS responder gives them; for one record, that record;
/// otherwise no such name.
fn answer(query: &Message, advertised: &Advertised) -> Message {
    let mut response = Message { id: query.id, response: true, authoritative: true, ..Message::default() };
    response.questions.clone_from(&query.questions);
    for question in &query.questions {
        let records = records(&question.name, advertised);
        let asked: Vec<&Record> =
            records.iter().filter(|r| r.name == question.name && r.kind == question.kind).collect();
        if asked.is_empty() {
            continue;
        }
        for record in asked {
            response.answers.push(record.clone());
        }
        if question.kind == dns::PTR {
            response.additionals.extend(records.iter().filter(|r| r.kind != dns::PTR).cloned());
        }
    }
    if response.answers.is_empty() {
        response.rcode = 3;
    }
    response
}

/// The records of the service a name is about, in the name's domain: the PTR of the
/// service type, the instance's SRV and TXT, and the host's address.
fn records(name: &Name, advertised: &Advertised) -> Vec<Record> {
    let labels = name.labels();
    // `<instance>._nmos-query._tcp.<domain>` or `_nmos-query._tcp.<domain>`, or the
    // host, `st2110-demo.<domain>`.
    let at = labels.iter().position(|l| l.starts_with("_nmos-"));
    let (kind, domain) = match at {
        Some(i) if labels.get(i + 1).is_some_and(|l| l.eq_ignore_ascii_case("_tcp")) => {
            (labels[i].to_ascii_lowercase(), labels[i + 2..].join("."))
        }
        _ if labels.first().is_some_and(|l| l.eq_ignore_ascii_case("st2110-demo")) => {
            (String::new(), labels[1..].join("."))
        }
        _ => return Vec::new(),
    };
    let address = match advertised.address.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => ip,
        _ => Ipv4Addr::LOCALHOST,
    };
    let host = Name::parse(&format!("st2110-demo.{domain}"));
    let a = Record::new(host.clone(), TTL, Data::A(address));
    let (instance, txt): (&str, Vec<&str>) = match kind.as_str() {
        "_nmos-query" => ("st2110 demo registry", vec!["api_proto=http", "api_ver=v1.0,v1.1,v1.2,v1.3", "pri=100"]),
        "_nmos-register" => ("st2110 demo registry", vec!["api_proto=http", "api_ver=v1.3", "pri=100"]),
        "_nmos-auth" if advertised.auth => {
            ("st2110 demo authorization", vec!["api_proto=http", "api_ver=v1.0", "pri=100"])
        }
        "" => return vec![a],
        _ => return Vec::new(),
    };
    let mut txt: Vec<Vec<u8>> = txt.into_iter().map(|t| t.as_bytes().to_vec()).collect();
    if kind != "_nmos-auth" {
        txt.push(format!("api_auth={}", advertised.auth).into_bytes());
    }
    let service = Name::parse(&format!("{kind}._tcp.{domain}"));
    let instance = service.child(instance);
    let srv = Data::Srv { priority: 0, weight: 0, port: advertised.address.port(), target: host };
    vec![
        Record::new(service, TTL, Data::Ptr(instance.clone())),
        Record::new(instance.clone(), TTL, srv),
        Record::new(instance, TTL, Data::Txt(txt)),
        a,
    ]
}

#[cfg(test)]
mod tests {
    use st2110_discover::dns::Question;

    use super::*;

    #[test]
    fn advertises_the_registry_in_any_domain() {
        let advertised = Advertised { address: "127.0.0.1:8110".parse().unwrap(), auth: true };
        let browse = Message::query(7, vec![Question::new(Name::parse("_nmos-query._tcp.demo.test"), dns::PTR)]);
        let response = answer(&browse, &advertised);
        assert_eq!((response.id, response.rcode, response.answers.len()), (7, 0, 1));
        assert_eq!(response.additionals.len(), 3);
        let srv = Message::query(
            8,
            vec![Question::new(Name::parse("st2110 demo registry._nmos-query._tcp.local"), dns::SRV)],
        );
        let Data::Srv { port, .. } = &answer(&srv, &advertised).answers[0].data else { panic!() };
        assert_eq!(*port, 8110);
        let auth = Message::query(9, vec![Question::new(Name::parse("_nmos-auth._tcp.demo.test"), dns::PTR)]);
        assert_eq!(answer(&auth, &advertised).answers.len(), 1);
        let without = Advertised { auth: false, ..advertised };
        assert_eq!(answer(&auth, &without).rcode, 3, "no Authorization Server without --demo-auth");
        let register = Message::query(11, vec![Question::new(Name::parse("_nmos-register._tcp.demo.test"), dns::PTR)]);
        assert_eq!(answer(&register, &without).answers.len(), 1);
        let other = Message::query(10, vec![Question::new(Name::parse("example.com"), dns::A)]);
        assert_eq!(answer(&other, &without).rcode, 3);
    }
}
