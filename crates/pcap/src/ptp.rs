//! The PTP messages in a capture, followed across it: each message checked against the
//! ST 2059-2 profile, and the exchanges between ports checked as a whole.

use std::collections::{BTreeMap, HashMap, VecDeque};

use st2110_ptp::{Body, Flags, Message, MessageType, PortIdentity};
use st2110_sdp::{ClockIdentity, Rule};

use crate::report::{Finding, MessageCount, PtpDomainReport, PtpPortReport, PtpReport};
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

/// The findings of one rule on one port's messages, kept once.
struct Checked {
    finding: st2110_ptp::Finding,
    domain: u8,
    port: PortIdentity,
    first: i128,
    count: u64,
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

/// Requests waiting for an answer, oldest first.
#[derive(Default)]
struct Waiting {
    pending: HashMap<(PortIdentity, u16), i128>,
    order: VecDeque<(i128, (PortIdentity, u16))>,
    unanswered: Tally,
    answered: u64,
}

impl Waiting {
    fn ask(&mut self, t: i128, key: (PortIdentity, u16)) {
        self.expire(t);
        self.pending.insert(key, t);
        self.order.push_back((t, key));
    }

    fn answer(&mut self, t: i128, key: (PortIdentity, u16)) {
        self.expire(t);
        if self.pending.remove(&key).is_some() {
            self.answered += 1;
        }
    }

    /// Counts the requests older than [`ANSWER_WITHIN`] at `now` as unanswered.
    fn expire(&mut self, now: i128) {
        while let Some(&(t, key)) = self.order.front() {
            if t >= now - ANSWER_WITHIN {
                break;
            }
            self.order.pop_front();
            if self.pending.remove(&key) == Some(t) {
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
}

impl Domain {
    fn port(&mut self, id: PortIdentity, address: &str) -> &mut Port {
        let i = *self.index.entry(id).or_insert_with(|| {
            self.ports.push(Port { id, address: address.to_string(), kinds: Vec::new(), last_announce: None });
            self.ports.len() - 1
        });
        &mut self.ports[i]
    }
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
    domains: BTreeMap<u8, Domain>,
    syncs: SyncTimes,
    checked: Vec<Checked>,
    checked_index: HashMap<(&'static str, u8, PortIdentity), usize>,
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

    /// Takes a message that arrived at `t` from `address`.
    pub(crate) fn push(&mut self, t: i128, address: &str, message: &Message) {
        self.messages += 1;
        let h = &message.header;
        if !self.domains.get(&h.domain).is_some_and(|d| d.index.contains_key(&h.source)) {
            if self.ports >= PORT_LIMIT {
                self.untracked += 1;
                return;
            }
            self.ports += 1;
        }
        for finding in st2110_ptp::check(message) {
            let key = (finding.rule, h.domain, h.source);
            match self.checked_index.get(&key) {
                Some(&i) => self.checked[i].count += 1,
                None => {
                    self.checked_index.insert(key, self.checked.len());
                    self.checked.push(Checked { finding, domain: h.domain, port: h.source, first: t, count: 1 });
                }
            }
        }
        let synced = self.syncs.push(t, message);
        let domain = self.domains.entry(h.domain).or_default();
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
        match &message.body {
            Body::Announce(announce) => {
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
            Body::Sync { .. } if h.flags.has(Flags::TWO_STEP) => domain.follow_ups.ask(t, (h.source, h.sequence_id)),
            Body::FollowUp { .. } => domain.follow_ups.answer(t, (h.source, h.sequence_id)),
            Body::DelayReq { .. } => domain.delay_responses.ask(t, (h.source, h.sequence_id)),
            Body::DelayResp { requesting, .. } => domain.delay_responses.answer(t, (*requesting, h.sequence_id)),
            _ => {}
        }
    }

    /// The report and findings, given the time the capture ended and the number of
    /// messages that could not be decoded.
    pub(crate) fn finish(mut self, end: i128, undecodable: u64, timeline: &Timeline) -> (PtpReport, Vec<Finding>) {
        let mut findings = Vec::new();
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
                domain: Some(c.domain),
                at: timeline.at(Some(c.first)),
                count: c.count,
            });
        }
        let mut domains = Vec::new();
        for (&number, domain) in &mut self.domains {
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
            domains.push(PtpDomainReport {
                domain: number,
                grandmasters: domain.grandmasters.iter().map(ToString::to_string).collect(),
                ports,
                sync_offset_us: domain.offsets.stats().filter(|_| on_ptp_time),
            });
        }
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
