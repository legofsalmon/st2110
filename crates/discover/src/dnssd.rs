//! DNS-SD (RFC 6763): the instances of a service type, and each one's host, port and
//! text pairs, put together from the records that multicast DNS responders and DNS
//! servers give.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::dns::{self, Data, Name, Question, Record, txt_pairs};

/// A service instance, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// Its full name, such as `Camera 1._nmos-node._tcp.local`.
    pub name: Name,
    /// Its own name, the first label of that: `Camera 1`.
    pub instance: String,
    /// The host it runs on, such as `camera-1.local`.
    pub host: Name,
    /// Its port.
    pub port: u16,
    /// The host's IPv4 addresses, as far as they are known, lowest first.
    pub addresses: Vec<Ipv4Addr>,
    /// Its text pairs, keys in lower case.
    pub txt: BTreeMap<String, String>,
}

struct Entry {
    record: Record,
    added: Instant,
    expires: Instant,
}

/// The records heard, each kept for as long as its time to live allows.
#[derive(Default)]
pub struct Cache {
    entries: Vec<Entry>,
}

impl Cache {
    /// Keeps a record heard at `now` for its time to live, or for `floor` where that is
    /// longer. A record with no time to live left removes its like (RFC 6762 §10.1), and
    /// one marked to flush the cache removes the older records of its name and type
    /// (RFC 6762 §10.2).
    pub fn add(&mut self, record: Record, now: Instant, floor: Duration) {
        if record.kind == dns::OPT || record.class != 1 {
            return;
        }
        let same = |e: &Entry| e.record.name == record.name && e.record.kind == record.kind;
        if record.ttl == 0 {
            self.entries.retain(|e| !(same(e) && e.record.data == record.data));
            return;
        }
        if record.cache_flush {
            let old = |e: &Entry| now.saturating_duration_since(e.added) > Duration::from_secs(1);
            self.entries.retain(|e| !(same(e) && old(e) && e.record.data != record.data));
        }
        let expires = now + Duration::from_secs(u64::from(record.ttl)).max(floor);
        match self.entries.iter_mut().find(|e| same(e) && e.record.data == record.data) {
            Some(e) => *e = Entry { record, added: now, expires },
            None => self.entries.push(Entry { record, added: now, expires }),
        }
    }

    /// Drops the records whose time is up; gives whether any were.
    pub fn expire(&mut self, now: Instant) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.expires > now);
        self.entries.len() != before
    }

    fn data<'s>(&'s self, name: &'s Name, kind: u16) -> impl Iterator<Item = &'s Data> + 's {
        self.entries.iter().filter(move |e| e.record.kind == kind && &e.record.name == name).map(|e| &e.record.data)
    }

    /// The instances of a service type, such as `_nmos-node._tcp.local`.
    pub fn instances(&self, service: &Name) -> Vec<Name> {
        let mut instances: Vec<Name> = self
            .data(service, dns::PTR)
            .filter_map(|d| match d {
                Data::Ptr(instance) => Some(instance.clone()),
                _ => None,
            })
            .collect();
        instances.sort_by_cached_key(ToString::to_string);
        instances.dedup();
        instances
    }

    /// An instance's host, port, addresses and text pairs, once its SRV record is known.
    pub fn resolve(&self, instance: &Name) -> Option<Service> {
        let (port, host) = self
            .data(instance, dns::SRV)
            .filter_map(|d| match d {
                Data::Srv { priority, port, target, .. } => Some((*priority, *port, target)),
                _ => None,
            })
            .min_by_key(|&(priority, port, _)| (priority, port))
            .map(|(_, port, target)| (port, target.clone()))?;
        let txt = self
            .data(instance, dns::TXT)
            .find_map(|d| match d {
                Data::Txt(strings) => Some(txt_pairs(strings)),
                _ => None,
            })
            .unwrap_or_default();
        let mut addresses: Vec<Ipv4Addr> = self
            .data(&host, dns::A)
            .filter_map(|d| match d {
                Data::A(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        let label = instance.labels().first().cloned().unwrap_or_default();
        Some(Service { name: instance.clone(), instance: label, host, port, addresses, txt })
    }

    /// The hosts that the SRV records name: those whose addresses are worth keeping.
    pub fn hosts(&self) -> Vec<Name> {
        let mut hosts: Vec<Name> = self
            .entries
            .iter()
            .filter_map(|e| match &e.record.data {
                Data::Srv { target, .. } => Some(target.clone()),
                _ => None,
            })
            .collect();
        hosts.sort_by_cached_key(ToString::to_string);
        hosts.dedup();
        hosts
    }

    /// What to ask next about the instances of `services`: the SRV and TXT records each
    /// one lacks, and the address of each host that lacks one.
    pub fn wanted(&self, services: &[Name]) -> Vec<Question> {
        let mut wanted = Vec::new();
        for service in services {
            for instance in self.instances(service) {
                for kind in [dns::SRV, dns::TXT] {
                    if self.data(&instance, kind).next().is_none() {
                        wanted.push(Question::new(instance.clone(), kind));
                    }
                }
                for data in self.data(&instance, dns::SRV) {
                    if let Data::Srv { target, .. } = data
                        && self.data(target, dns::A).next().is_none()
                    {
                        wanted.push(Question::new(target.clone(), dns::A));
                    }
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        wanted.retain(|q| seen.insert(q.clone()));
        wanted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Name {
        Name::parse("_nmos-node._tcp.local")
    }

    fn records(instance: &str, host: &str, port: u16, address: Ipv4Addr) -> Vec<Record> {
        let name = service().child(instance);
        let host = Name::parse(host);
        let txt: Vec<Vec<u8>> = ["api_proto=http", "api_ver=v1.3", "API_AUTH=false"].map(|s| s.into()).to_vec();
        vec![
            Record::new(service(), 4500, Data::Ptr(name.clone())),
            Record::new(name.clone(), 120, Data::Srv { priority: 0, weight: 0, port, target: host.clone() }),
            Record::new(name, 4500, Data::Txt(txt)),
            Record::new(host, 120, Data::A(address)),
        ]
    }

    #[test]
    fn resolves_instances_from_their_records() {
        let now = Instant::now();
        let mut cache = Cache::default();
        let [ptr, srv, txt, a] =
            records("Camera 1", "camera-1.local", 80, Ipv4Addr::new(192, 168, 10, 21)).try_into().unwrap();
        cache.add(ptr, now, Duration::ZERO);
        let instance = service().child("Camera 1");
        assert_eq!(cache.instances(&service()), std::slice::from_ref(&instance));
        assert_eq!(cache.resolve(&instance), None, "not without its SRV record");
        let ask = |kind| Question::new(instance.clone(), kind);
        assert_eq!(cache.wanted(&[service()]), [ask(dns::SRV), ask(dns::TXT)]);
        cache.add(srv, now, Duration::ZERO);
        cache.add(txt, now, Duration::ZERO);
        assert_eq!(cache.wanted(&[service()]), [Question::new(Name::parse("camera-1.local"), dns::A)]);
        cache.add(a, now, Duration::ZERO);
        assert!(cache.wanted(&[service()]).is_empty());
        let resolved = cache.resolve(&instance).unwrap();
        assert_eq!((resolved.instance.as_str(), resolved.port), ("Camera 1", 80));
        assert_eq!(resolved.addresses, [Ipv4Addr::new(192, 168, 10, 21)]);
        assert_eq!(resolved.txt["api_auth"], "false");
        // The SRV and address records go when their time is up, and are asked for again.
        assert!(cache.expire(now + Duration::from_secs(121)));
        assert_eq!(cache.resolve(&instance), None);
        assert_eq!(cache.wanted(&[service()]), [ask(dns::SRV)]);
        assert!(!cache.expire(now + Duration::from_secs(4499)) && cache.expire(now + Duration::from_secs(4501)));
        assert!(cache.instances(&service()).is_empty());
    }

    #[test]
    fn says_goodbye_and_flushes() {
        let now = Instant::now();
        let mut cache = Cache::default();
        for record in records("Camera 1", "camera-1.local", 80, Ipv4Addr::new(192, 168, 10, 21)) {
            cache.add(record, now, Duration::ZERO);
        }
        // The host moves to a new address, flushing the old a second and more later.
        let mut moved = Record::new(Name::parse("camera-1.local"), 120, Data::A(Ipv4Addr::new(192, 168, 10, 99)));
        moved.cache_flush = true;
        cache.add(moved.clone(), now + Duration::from_secs(2), Duration::ZERO);
        let instance = service().child("Camera 1");
        assert_eq!(cache.resolve(&instance).unwrap().addresses, [Ipv4Addr::new(192, 168, 10, 99)]);
        // The instance says goodbye.
        let mut goodbye = Record::new(service(), 0, Data::Ptr(instance.clone()));
        goodbye.cache_flush = true;
        cache.add(goodbye, now, Duration::ZERO);
        assert!(cache.instances(&service()).is_empty());
        // A short time to live, raised to the floor.
        let mut cache = Cache::default();
        let mut brief = records("Camera 2", "camera-2.local", 80, Ipv4Addr::new(192, 168, 10, 22));
        brief.iter_mut().for_each(|r| r.ttl = 10);
        brief.into_iter().for_each(|r| cache.add(r, now, Duration::from_secs(60)));
        assert!(!cache.expire(now + Duration::from_secs(59)) && cache.expire(now + Duration::from_secs(61)));
    }
}
