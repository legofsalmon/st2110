//! The PTP messages in a capture, followed across it: each message checked against the
//! ST 2059-2 profile, and the exchanges between ports checked as a whole.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;

use st2110_ptp::describe::clock_class;
use st2110_ptp::{Body, Flags, LockingStatus, Message, MessageType, PortIdentity, TlvContent};
use st2110_sdp::{ClockIdentity, RefClock, Rule};

use crate::report::{
    Finding, GrandmasterQuality, LockingChange, MessageCount, PtpDomainReport, PtpPortReport, PtpReport,
    SyncMetadataReport,
};
use crate::stats::{Accumulator, NANOS, Tally};
use crate::timescale::SyncTimes;
use crate::{PORT_LIMIT, Timeline, plural, rules};

/// How long a Sync waits for its Follow_Up, or a Delay_Req for its Delay_Resp.
const ANSWER_WITHIN: i128 = NANOS;

/// The mean interval between Announce or Sync messages may stray this far, as a
/// fraction, from the one logMessageInterval gives.
const RATE_TOLERANCE: f64 = 0.3;

/// Messages a port may have sent before its interval is worth judging.
const RATE_MIN_INTERVALS: u64 = 4;

/// Grandmasters, and ports announcing at once, named in a domain's findings, at most.
const NAMES: usize = 16;

/// Changes of the grandmaster's quality, or of its locking status, kept for the report,
/// at most.
const CHANGES: usize = 64;

/// Changes named in a finding's message, at most.
const CHANGES_NAMED: usize = 8;

/// The grandmaster sends the synchronization metadata TLV once a second (ST 2059-2
/// §6.12): a longer gap than this between two from one port means one went missing.
const SM_TLV_GAP: i128 = 3 * NANOS / 2;

/// A domain announced for this long with no synchronization metadata TLV at all had a
/// grandmaster that sent none.
const SM_TLV_WITHIN: i128 = 3 * NANOS;

/// The poorest clockAccuracy a grandmaster may have and still be called traceable in an
/// SDP file: within 250 ns (ST 2110-10 §8.2).
const TRACEABLE_ACCURACY: u8 = 0x22;

/// A PTP domain: its number, its sdoId, and whether it runs over Ethernet. Profiles
/// that share a number, such as gPTP and AES67 on domain 0, are kept apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DomainKey {
    number: u8,
    sdo_id: u16,
    layer2: bool,
}

impl DomainKey {
    /// Whether the ST 2059-2 profile governs it: sdoId 0, over UDP (§6.9).
    fn st2059(self) -> bool {
        self.sdo_id == 0 && !self.layer2
    }
}

/// The findings of one rule on one port's messages, kept once.
struct Checked {
    finding: st2110_ptp::Finding,
    domain: DomainKey,
    port: PortIdentity,
    first: i128,
    count: u64,
}

/// Messages that went to a multicast group, and to one address.
#[derive(Default)]
struct Modes {
    multicast: Tally,
    unicast: Tally,
}

impl Modes {
    fn hit(&mut self, t: i128, multicast: bool) {
        if multicast { self.multicast.hit(t) } else { self.unicast.hit(t) }
    }
}

/// A grandmaster and its quality, as an Announce message gave them.
#[derive(Clone, Copy, PartialEq)]
struct Quality {
    grandmaster: ClockIdentity,
    class: u8,
    accuracy: u8,
    variance: u16,
    time_source: u8,
    ptp_timescale: bool,
    time_traceable: bool,
}

impl Quality {
    /// Why an SDP file could not call it traceable (ST 2110-10 §8.2), if it could not.
    fn untraceable(&self) -> Option<String> {
        let mut why = Vec::new();
        if !self.ptp_timescale {
            why.push("it is not on the PTP timescale".to_string());
        }
        if !self.time_traceable {
            why.push("timeTraceable is clear".to_string());
        }
        // 17h to 22h: 1 ps to 250 ns. Smaller values are reserved, larger ones poorer.
        if !(0x17..=TRACEABLE_ACCURACY).contains(&self.accuracy) {
            why.push(format!("clockAccuracy {:02X}h is not within 250 ns", self.accuracy));
        }
        (!why.is_empty()).then(|| format!("grandmaster {}: {}", self.grandmaster, why.join(", ")))
    }
}

/// `class 6 to 7 (in holdover)`, or the accuracy that changed.
fn quality_change(before: &Quality, after: &Quality) -> String {
    let mut parts = Vec::new();
    if before.class != after.class {
        parts.push(format!("class {} to {} ({})", before.class, after.class, clock_class(after.class)));
    }
    if before.accuracy != after.accuracy {
        parts.push(format!("accuracy {:02X}h to {:02X}h", before.accuracy, after.accuracy));
    }
    parts.join(", ")
}

/// Messages of one type from one port.
struct Kind {
    kind: MessageType,
    count: u64,
    log: Option<i8>,
    last: Option<(u16, i128)>,
    interval: Accumulator,
}

struct Port {
    id: PortIdentity,
    address: String,
    kinds: Vec<Kind>,
    last_announce: Option<i128>,
    /// When its last synchronization metadata TLV came, and the gaps longer than
    /// [`SM_TLV_GAP`] between its TLVs.
    last_metadata: Option<i128>,
    metadata_gaps: Tally,
}

impl Port {
    fn kind(&mut self, kind: MessageType) -> &mut Kind {
        let i = match self.kinds.iter().position(|k| k.kind == kind) {
            Some(i) => i,
            None => {
                self.kinds.push(Kind { kind, count: 0, log: None, last: None, interval: Accumulator::default() });
                self.kinds.len() - 1
            }
        };
        &mut self.kinds[i]
    }
}

/// Requests waiting for an answer, oldest first, with whether each went multicast.
#[derive(Default)]
struct Waiting {
    pending: HashMap<(PortIdentity, u16), (i128, bool)>,
    order: VecDeque<(i128, (PortIdentity, u16))>,
    unanswered: Tally,
    answered: u64,
}

impl Waiting {
    fn ask(&mut self, t: i128, key: (PortIdentity, u16), multicast: bool) {
        self.expire(t);
        self.pending.insert(key, (t, multicast));
        self.order.push_back((t, key));
    }

    /// Takes an answer, and gives whether its request went multicast, if it was waiting.
    fn answer(&mut self, t: i128, key: (PortIdentity, u16)) -> Option<bool> {
        self.expire(t);
        let (_, multicast) = self.pending.remove(&key)?;
        self.answered += 1;
        Some(multicast)
    }

    /// Counts the requests older than [`ANSWER_WITHIN`] at `now` as unanswered.
    fn expire(&mut self, now: i128) {
        while let Some(&(t, key)) = self.order.front() {
            if t >= now - ANSWER_WITHIN {
                break;
            }
            self.order.pop_front();
            if self.pending.get(&key).is_some_and(|&(asked, _)| asked == t) {
                self.pending.remove(&key);
                self.unanswered.hit(t);
            }
        }
    }
}

#[derive(Default)]
struct Domain {
    /// The first [`NAMES`] grandmasters, and whether there were more.
    grandmasters: Vec<ClockIdentity>,
    more_grandmasters: bool,
    grandmaster: Option<ClockIdentity>,
    grandmaster_changes: Tally,
    ports: Vec<Port>,
    index: HashMap<PortIdentity, usize>,
    last_announcer: Option<PortIdentity>,
    rivals: Tally,
    /// The first [`NAMES`] ports that announced while another did, and whether there were more.
    rival_ports: Vec<PortIdentity>,
    more_rival_ports: bool,
    /// Whether an Announce said ptpTimescale, and whether one said not.
    ptp_timescale: bool,
    arbitrary: bool,
    offsets: Accumulator,
    follow_ups: Waiting,
    delay_responses: Waiting,
    /// When Announce messages came, the first and the last.
    announced: Option<(i128, i128)>,
    /// The grandmaster's quality: the first, then each change, up to [`CHANGES`]; and
    /// the changes of class or accuracy while the grandmaster stayed the same.
    quality: Vec<(i128, Quality)>,
    last_quality: Option<Quality>,
    quality_changes: Tally,
    quality_named: Vec<(i128, String)>,
    /// Why the first grandmaster that an SDP file could not call traceable could not be.
    untraceable: Option<String>,
    /// Synchronization metadata TLVs, the intervals between one port's, and the locking
    /// status: the first, then each change, up to [`CHANGES`].
    metadata: u64,
    metadata_intervals: Accumulator,
    locking: Vec<(i128, LockingStatus)>,
    last_locking: Option<LockingStatus>,
    locking_changes: Tally,
    locking_named: Vec<(i128, String)>,
    /// How messages went (ST 2059-2 §6.10): Announce, Sync and Follow_Up; the
    /// synchronization metadata; Delay_Req; and Delay_Resp messages that went otherwise
    /// than their Delay_Req came.
    general: Modes,
    metadata_modes: Modes,
    delay_requests: Modes,
    delay_mode_mismatch: Tally,
}

impl Domain {
    fn port(&mut self, id: PortIdentity, address: &str) -> &mut Port {
        let i = *self.index.entry(id).or_insert_with(|| {
            self.ports.push(Port {
                id,
                address: address.to_string(),
                kinds: Vec::new(),
                last_announce: None,
                last_metadata: None,
                metadata_gaps: Tally::default(),
            });
            self.ports.len() - 1
        });
        &mut self.ports[i]
    }

    /// Takes the grandmaster and its quality from an Announce message at `t`.
    fn announce_quality(&mut self, t: i128, quality: Quality) {
        let Some(before) = self.last_quality.replace(quality) else {
            self.untraceable = quality.untraceable();
            self.quality.push((t, quality));
            return;
        };
        if before == quality {
            return;
        }
        if before.grandmaster == quality.grandmaster
            && (before.class, before.accuracy) != (quality.class, quality.accuracy)
        {
            self.quality_changes.hit(t);
            if self.quality_named.len() < CHANGES_NAMED {
                self.quality_named.push((t, quality_change(&before, &quality)));
            }
        }
        if self.untraceable.is_none() {
            self.untraceable = quality.untraceable();
        }
        if self.quality.len() < CHANGES {
            self.quality.push((t, quality));
        }
    }

    /// Takes a synchronization metadata TLV that came at `t` from port `id`.
    fn metadata_tlv(&mut self, t: i128, address: &str, id: PortIdentity, multicast: bool, status: LockingStatus) {
        self.metadata += 1;
        self.metadata_modes.hit(t, multicast);
        let port = self.port(id, address);
        let last = port.last_metadata.replace(t);
        if let Some(last) = last {
            if t - last > SM_TLV_GAP {
                port.metadata_gaps.hit_max(t, (t - last) as f64 / 1e9);
            }
            self.metadata_intervals.add((t - last) as f64 / 1e6);
        }
        match self.last_locking.replace(status) {
            Some(before) if before == status => {}
            Some(before) => {
                self.locking_changes.hit(t);
                if self.locking_named.len() < CHANGES_NAMED {
                    self.locking_named.push((t, format!("{} to {}", before.describe(), status.describe())));
                }
                if self.locking.len() < CHANGES {
                    self.locking.push((t, status));
                }
            }
            None => self.locking.push((t, status)),
        }
    }

    /// The findings across the ports of an ST 2059-2 domain, numbered `number`, whose
    /// capture ended at `end`.
    fn profile_findings(&self, number: u8, end: i128, timeline: &Timeline) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut add = |rule: &'static Rule, message: String, first: Option<i128>, count: u64| {
            findings.push(Finding::new(rule, message, None, Some(number), timeline.at(first), count));
        };
        let log = |port: &Port, kind: MessageType| port.kinds.iter().find(|k| k.kind == kind).and_then(|k| k.log);

        // §6.5.2: one Announce interval throughout the domain.
        let mut announce: Vec<(i8, Vec<String>)> = Vec::new();
        for port in &self.ports {
            let Some(value) = log(port, MessageType::Announce) else { continue };
            match announce.iter_mut().find(|(v, _)| *v == value) {
                Some((_, ports)) => ports.push(port.id.to_string()),
                None => announce.push((value, vec![port.id.to_string()])),
            }
        }
        if announce.len() > 1 {
            announce.sort_by_key(|(value, _)| *value);
            let each: Vec<String> =
                announce.iter().map(|(value, ports)| format!("{value} from {}", names(ports, false))).collect();
            add(
                &rules::PTP_ANNOUNCE_UNIFORM,
                format!("Announce messages gave logMessageInterval {}", each.join("; ")),
                None,
                announce.iter().map(|(_, ports)| ports.len() as u64).sum(),
            );
        }

        // §6.5.3: logMinDelayReqInterval from logSyncInterval to 5 more.
        for port in &self.ports {
            let (Some(sync), Some(delay)) = (log(port, MessageType::Sync), log(port, MessageType::DelayResp)) else {
                continue;
            };
            if !(i16::from(sync)..=i16::from(sync) + 5).contains(&i16::from(delay)) {
                let count = port.kinds.iter().find(|k| k.kind == MessageType::DelayResp).map_or(0, |k| k.count);
                add(
                    &rules::PTP_DELAY_REQ_RANGE,
                    format!(
                        "{} sent Delay_Resp messages with logMinDelayReqInterval {delay}, outside {sync} to {} for its logSyncInterval {sync}",
                        port.id,
                        i16::from(sync) + 5
                    ),
                    None,
                    count,
                );
            }
        }

        // §6.10: how each kind of message goes.
        let (general, metadata, requests) = (&self.general, &self.metadata_modes, &self.delay_requests);
        let mut problems = Vec::new();
        let mut tallies = Vec::new();
        if general.multicast.count > 0 && general.unicast.count > 0 {
            problems.push(format!(
                "Announce, Sync and Follow_Up messages went both multicast ({}) and unicast ({})",
                general.multicast.count, general.unicast.count
            ));
            tallies.push(general.unicast);
        } else if general.multicast.count > 0 && metadata.unicast.count > 0 {
            problems.push(format!(
                "{} went unicast, while Announce, Sync and Follow_Up went multicast",
                plural(metadata.unicast.count, "synchronization metadata message")
            ));
            tallies.push(metadata.unicast);
        } else if general.unicast.count > 0 && metadata.multicast.count > 0 {
            problems.push(format!(
                "{} went multicast, while Announce, Sync and Follow_Up went unicast",
                plural(metadata.multicast.count, "synchronization metadata message")
            ));
            tallies.push(metadata.multicast);
        }
        if self.delay_mode_mismatch.count > 0 {
            problems.push(format!(
                "{} went otherwise than its Delay_Req came",
                plural(self.delay_mode_mismatch.count, "Delay_Resp message")
            ));
            tallies.push(self.delay_mode_mismatch);
        }
        if general.unicast.count > 0 && requests.multicast.count > 0 {
            problems.push(format!(
                "Announce, Sync or Follow_Up messages went unicast, as in unicast mode, beside {} sent multicast, as in multicast mode; unicast mode shares a domain with no other",
                plural(requests.multicast.count, "Delay_Req message")
            ));
            tallies.push(requests.multicast);
        }
        if !problems.is_empty() {
            add(
                &rules::PTP_TRANSPORT_MODE,
                problems.join("; "),
                tallies.iter().filter_map(|t| t.first).min(),
                tallies.iter().map(|t| t.count).sum(),
            );
        }

        // §6.12: the synchronization metadata once a second.
        for port in &self.ports {
            let gaps = &port.metadata_gaps;
            if gaps.count > 0 {
                add(
                    &rules::PTP_SM_TLV_RATE,
                    format!(
                        "{} let more than 1.5 s pass between synchronization metadata TLVs {}, at most {:.1} s",
                        port.id,
                        plural(gaps.count, "time"),
                        gaps.worst.unwrap_or_default()
                    ),
                    gaps.first,
                    gaps.count,
                );
            }
        }
        if let Some((first, last)) = self.announced
            && self.metadata == 0
            && last - first >= SM_TLV_WITHIN
        {
            add(
                &rules::PTP_SM_TLV_RATE,
                format!(
                    "no synchronization metadata TLV came in {:.1} s of Announce messages",
                    (last.min(end) - first) as f64 / 1e9
                ),
                Some(first),
                1,
            );
        }
        let changes = |named: &[(i128, String)], more: u64| {
            let mut text = named
                .iter()
                .map(|(t, change)| format!("at {:.3} s {change}", timeline.at(Some(*t)).unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(", ");
            if more > named.len() as u64 {
                text.push_str(", and others");
            }
            text
        };
        if self.locking_changes.count > 0 {
            add(
                &rules::PTP_SM_LOCKING,
                format!(
                    "gmLockingStatus changed {}: {}",
                    plural(self.locking_changes.count, "time"),
                    changes(&self.locking_named, self.locking_changes.count)
                ),
                self.locking_changes.first,
                self.locking_changes.count,
            );
        }
        if self.quality_changes.count > 0 {
            add(
                &rules::PTP_GM_QUALITY,
                format!(
                    "the grandmaster's quality changed {}: {}",
                    plural(self.quality_changes.count, "time"),
                    changes(&self.quality_named, self.quality_changes.count)
                ),
                self.quality_changes.first,
                self.quality_changes.count,
            );
        }
        findings
    }
}

/// Compares the reference clock each SDP stream names (ST 2110-10 §8.2) with the
/// grandmasters of the ST 2059-2 domains whose Announce messages the capture holds.
fn refclk_findings(domains: &[(u8, &Domain)], refclks: &[(String, RefClock)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if domains.is_empty() {
        return findings;
    }
    // Streams that name the same clock are reported together.
    let mut claims: Vec<(&RefClock, Vec<&str>)> = Vec::new();
    for (label, clock) in refclks.iter().filter(|(_, c)| matches!(c, RefClock::Ptp { .. })) {
        match claims.iter_mut().find(|(c, _)| *c == clock) {
            Some((_, labels)) => labels.push(label),
            None => claims.push((clock, vec![label])),
        }
    }
    let numbers = names(&domains.iter().map(|(n, _)| *n).collect::<Vec<_>>(), false);
    for (clock, labels) in claims {
        let RefClock::Ptp { grandmaster, domain, traceable, .. } = clock else { continue };
        let streams = labels.join(", ");
        let (says, name) = if labels.len() == 1 { ("says", "names") } else { ("say", "name") };
        let found = |number: u8| domains.iter().find(|(n, _)| *n == number).map(|(_, d)| *d);
        let (message, domain) = match (grandmaster, domain) {
            _ if *traceable => {
                if domains.iter().any(|(_, d)| d.untraceable.is_none()) {
                    continue;
                }
                let why = domains.iter().find_map(|(_, d)| d.untraceable.clone()).unwrap_or_default();
                (format!("{streams} {says} the PTP is traceable, but {why}"), None)
            }
            (Some(gm), Some(number)) => match found(*number) {
                None => (
                    format!(
                        "{streams} {name} grandmaster {gm} in domain {number}, but the capture's Announce messages are in domain {numbers}"
                    ),
                    None,
                ),
                Some(d) if !d.grandmasters.contains(gm) => (
                    format!(
                        "{streams} {name} grandmaster {gm} in domain {number}, but its Announce messages named {}",
                        names(&d.grandmasters, d.more_grandmasters)
                    ),
                    Some(*number),
                ),
                Some(_) => continue,
            },
            (Some(gm), None) => {
                if domains.iter().any(|(_, d)| d.grandmasters.contains(gm)) {
                    continue;
                }
                (
                    format!("{streams} {name} grandmaster {gm}, which no Announce message in domain {numbers} named"),
                    None,
                )
            }
            (None, _) => continue,
        };
        findings.push(Finding::new(&rules::PTP_REFCLK, message, None, domain, None, labels.len() as u64));
    }
    findings
}

/// Adds `item` to a list of names kept to [`NAMES`], noting in `more` any it leaves out.
fn name<T: PartialEq>(names: &mut Vec<T>, more: &mut bool, item: T) {
    if !names.contains(&item) {
        if names.len() < NAMES {
            names.push(item);
        } else {
            *more = true;
        }
    }
}

/// Names, then `and others` when some were left out.
fn names<T: ToString>(names: &[T], more: bool) -> String {
    let mut text = names.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    if more {
        text.push_str(" and others");
    }
    text
}

pub(crate) struct Monitor {
    absolute: bool,
    messages: u64,
    /// Ports followed, across the domains.
    ports: usize,
    /// Messages from ports past the first [`PORT_LIMIT`].
    untracked: u64,
    domains: BTreeMap<DomainKey, Domain>,
    syncs: SyncTimes,
    checked: Vec<Checked>,
    checked_index: HashMap<(&'static str, DomainKey, PortIdentity), usize>,
}

impl Monitor {
    pub(crate) fn new(absolute: bool) -> Self {
        Self {
            absolute,
            messages: 0,
            ports: 0,
            untracked: 0,
            domains: BTreeMap::new(),
            syncs: SyncTimes::default(),
            checked: Vec::new(),
            checked_index: HashMap::new(),
        }
    }

    /// Takes a message that arrived at `t` from `address`, sent to `to`: an IP address,
    /// or `None` over Ethernet.
    pub(crate) fn push(&mut self, t: i128, address: &str, to: Option<IpAddr>, message: &Message) {
        self.messages += 1;
        let h = &message.header;
        let layer2 = to.is_none();
        let multicast = to.is_some_and(|to| to.is_multicast());
        let key =
            DomainKey { number: h.domain, sdo_id: u16::from(h.major_sdo_id) << 8 | u16::from(h.minor_sdo_id), layer2 };
        if !self.domains.get(&key).is_some_and(|d| d.index.contains_key(&h.source)) {
            if self.ports >= PORT_LIMIT {
                self.untracked += 1;
                return;
            }
            self.ports += 1;
        }
        // Other profiles, such as gPTP, keep their own rules.
        let findings = if key.st2059() { st2110_ptp::check(message) } else { Vec::new() };
        for finding in findings {
            let index = (finding.rule, key, h.source);
            match self.checked_index.get(&index) {
                Some(&i) => self.checked[i].count += 1,
                None => {
                    self.checked_index.insert(index, self.checked.len());
                    self.checked.push(Checked { finding, domain: key, port: h.source, first: t, count: 1 });
                }
            }
        }
        let synced = self.syncs.push(t, message);
        let domain = self.domains.entry(key).or_default();
        if let Some((_, arrival, left)) = synced
            && self.absolute
        {
            domain.offsets.add((arrival - left) as f64 / 1000.0);
        }
        let port = domain.port(h.source, address);
        let kind = port.kind(h.message_type);
        kind.count += 1;
        if h.log_message_interval != 127 {
            kind.log = Some(h.log_message_interval);
        }
        if let Some((seq, last)) = kind.last
            && h.sequence_id == seq.wrapping_add(1)
        {
            kind.interval.add((t - last) as f64 / 1e6);
        }
        kind.last = Some((h.sequence_id, t));
        if matches!(message.body, Body::Announce(_) | Body::Sync { .. } | Body::FollowUp { .. }) {
            domain.general.hit(t, multicast);
        }
        let locking = message.tlvs.iter().find_map(|tlv| match &tlv.content {
            TlvContent::SyncMetadata(sm) => Some(sm.locking_status),
            _ => None,
        });
        if let Some(status) = locking {
            domain.metadata_tlv(t, address, h.source, multicast, status);
        }
        match &message.body {
            Body::Announce(announce) => {
                domain.announced = Some(domain.announced.map_or((t, t), |(first, _)| (first, t)));
                domain.announce_quality(
                    t,
                    Quality {
                        grandmaster: announce.grandmaster,
                        class: announce.quality.class,
                        accuracy: announce.quality.accuracy,
                        variance: announce.quality.variance,
                        time_source: announce.time_source,
                        ptp_timescale: h.flags.has(Flags::PTP_TIMESCALE),
                        time_traceable: h.flags.has(Flags::TIME_TRACEABLE),
                    },
                );
                if h.flags.has(Flags::PTP_TIMESCALE) {
                    domain.ptp_timescale = true;
                } else {
                    domain.arbitrary = true;
                }
                // Another port announcing between two of this port's Announces, both
                // well within the time a receiver waits for one, means two masters.
                let within = 4.0 * 2f64.powi(i32::from(h.log_message_interval.clamp(-7, 4)));
                let previous = domain.port(h.source, address).last_announce;
                if let (Some(last), Some(previous)) = (domain.last_announcer, previous)
                    && last != h.source
                    && ((t - previous) as f64) < within * 1e9
                {
                    domain.rivals.hit(t);
                    for id in [last, h.source] {
                        name(&mut domain.rival_ports, &mut domain.more_rival_ports, id);
                    }
                }
                domain.port(h.source, address).last_announce = Some(t);
                domain.last_announcer = Some(h.source);
                let gm = announce.grandmaster;
                if domain.grandmaster.is_some_and(|current| current != gm) {
                    domain.grandmaster_changes.hit(t);
                }
                domain.grandmaster = Some(gm);
                name(&mut domain.grandmasters, &mut domain.more_grandmasters, gm);
            }
            Body::Sync { .. } if h.flags.has(Flags::TWO_STEP) => {
                domain.follow_ups.ask(t, (h.source, h.sequence_id), multicast);
            }
            Body::FollowUp { .. } => {
                domain.follow_ups.answer(t, (h.source, h.sequence_id));
            }
            Body::DelayReq { .. } => {
                domain.delay_requests.hit(t, multicast);
                domain.delay_responses.ask(t, (h.source, h.sequence_id), multicast);
            }
            Body::DelayResp { requesting, .. } => {
                let asked = domain.delay_responses.answer(t, (*requesting, h.sequence_id));
                if asked.is_some_and(|asked| asked != multicast) {
                    domain.delay_mode_mismatch.hit(t);
                }
            }
            _ => {}
        }
    }

    /// The report and findings, given the time the capture ended and the number of
    /// messages that could not be decoded.
    pub(crate) fn finish(
        mut self,
        end: i128,
        undecodable: u64,
        timeline: &Timeline,
        refclks: &[(String, RefClock)],
    ) -> (PtpReport, Vec<Finding>) {
        let mut findings = Vec::new();
        // ST 2059-2 domains where Announce messages came, for the SDP files' ts-refclk.
        let mut profiled: Vec<(u8, &Domain)> = Vec::new();
        for c in &self.checked {
            let mut message = format!("{}: {}", c.port, c.finding.message);
            if c.count > 1 {
                message.push_str(&format!(" ({} messages)", c.count));
            }
            findings.push(Finding {
                rule: c.finding.rule,
                severity: c.finding.severity,
                message,
                reference: c.finding.reference,
                flow: None,
                domain: Some(c.domain.number),
                at: timeline.at(Some(c.first)),
                count: c.count,
            });
        }
        let mut domains = Vec::new();
        for (&key, domain) in &mut self.domains {
            let number = key.number;
            // Requests near the end may have been answered after the capture stopped.
            domain.follow_ups.expire(end);
            domain.delay_responses.expire(end);
            let mut add = |rule: &'static Rule, tally: &Tally, message: String| {
                if tally.count > 0 {
                    findings.push(Finding::new(
                        rule,
                        message,
                        None,
                        Some(number),
                        timeline.at(tally.first),
                        tally.count,
                    ));
                }
            };
            add(
                &rules::PTP_GRANDMASTER_CHANGE,
                &domain.grandmaster_changes,
                format!(
                    "the grandmaster changed {} between {}",
                    plural(domain.grandmaster_changes.count, "time"),
                    names(&domain.grandmasters, domain.more_grandmasters)
                ),
            );
            add(
                &rules::PTP_MASTERS,
                &domain.rivals,
                format!(
                    "{} came from one port while another was announcing too; the ports: {}",
                    plural(domain.rivals.count, "Announce message"),
                    names(&domain.rival_ports, domain.more_rival_ports)
                ),
            );
            add(
                &rules::PTP_FOLLOW_UP,
                &domain.follow_ups.unanswered,
                format!(
                    "{} had no Follow_Up within a second",
                    plural(domain.follow_ups.unanswered.count, "two-step Sync message")
                ),
            );
            // Delay_Resp messages may go where the capture cannot see them, so only
            // gaps among those it does see count.
            if domain.delay_responses.answered > 0 {
                add(
                    &rules::PTP_DELAY_RESP,
                    &domain.delay_responses.unanswered,
                    format!(
                        "{} had no Delay_Resp within a second, while {} did",
                        plural(domain.delay_responses.unanswered.count, "Delay_Req message"),
                        domain.delay_responses.answered
                    ),
                );
            }
            for port in &domain.ports {
                for kind in port.kinds.iter().filter(|k| matches!(k.kind, MessageType::Announce | MessageType::Sync)) {
                    let (Some(log), Some(stats)) = (kind.log, kind.interval.stats()) else { continue };
                    let expected = 2f64.powi(i32::from(log)) * 1000.0;
                    if stats.count >= RATE_MIN_INTERVALS && (stats.mean / expected - 1.0).abs() > RATE_TOLERANCE {
                        findings.push(Finding::new(
                            &rules::PTP_MESSAGE_RATE,
                            format!(
                                "{} sent {} messages every {:.1} ms on average, not the {expected:.1} ms that logMessageInterval {log} gives",
                                port.id, kind.kind, stats.mean
                            ),
                            None,
                            Some(number),
                            None,
                            stats.count,
                        ));
                    }
                }
            }
            let on_ptp_time = domain.ptp_timescale || !domain.arbitrary;
            let mut ports: Vec<PtpPortReport> = domain
                .ports
                .iter()
                .map(|p| {
                    let mut kinds: Vec<&Kind> = p.kinds.iter().collect();
                    kinds.sort_by_key(|k| order(k.kind));
                    PtpPortReport {
                        port: p.id.to_string(),
                        address: p.address.clone(),
                        messages: kinds
                            .into_iter()
                            .map(|k| MessageCount {
                                kind: k.kind.to_string(),
                                count: k.count,
                                log_interval: k.log,
                                interval_ms: k.interval.stats(),
                            })
                            .collect(),
                    }
                })
                .collect();
            ports.sort_by(|a, b| a.port.cmp(&b.port));
            if key.st2059() {
                findings.extend(domain.profile_findings(number, end, timeline));
            }
            let at = |t: i128| timeline.at(Some(t)).unwrap_or_default();
            domains.push(PtpDomainReport {
                domain: number,
                sdo_id: key.sdo_id,
                layer2: key.layer2,
                grandmasters: domain.grandmasters.iter().map(ToString::to_string).collect(),
                ports,
                sync_offset_us: domain.offsets.stats().filter(|_| on_ptp_time),
                quality: domain
                    .quality
                    .iter()
                    .map(|(t, q)| GrandmasterQuality {
                        at: at(*t),
                        grandmaster: q.grandmaster.to_string(),
                        class: q.class,
                        accuracy: q.accuracy,
                        variance: q.variance,
                        time_source: q.time_source,
                        ptp_timescale: q.ptp_timescale,
                        time_traceable: q.time_traceable,
                    })
                    .collect(),
                sync_metadata: (domain.metadata > 0).then(|| SyncMetadataReport {
                    messages: domain.metadata,
                    interval_ms: domain.metadata_intervals.stats(),
                    locking: domain
                        .locking
                        .iter()
                        .map(|(t, status)| LockingChange { at: at(*t), status: status.describe() })
                        .collect(),
                }),
            });
            if key.st2059() && domain.announced.is_some() {
                profiled.push((number, domain));
            }
        }
        findings.extend(refclk_findings(&profiled, refclks));
        (PtpReport { messages: self.messages, undecodable, untracked: self.untracked, domains }, findings)
    }
}

/// Message types in the order IEEE 1588 numbers them.
fn order(kind: MessageType) -> u8 {
    match kind {
        MessageType::Sync => 0,
        MessageType::DelayReq => 1,
        MessageType::PdelayReq => 2,
        MessageType::PdelayResp => 3,
        MessageType::FollowUp => 8,
        MessageType::DelayResp => 9,
        MessageType::PdelayRespFollowUp => 10,
        MessageType::Announce => 11,
        MessageType::Signaling => 12,
        MessageType::Management => 13,
        MessageType::Reserved(n) => n,
    }
}
