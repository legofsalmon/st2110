//! The status monitor of the Node's one Receiver or Sender (BCP-008-01 v1.0, BCP-008-02
//! v1.0): each domain's status from what the stream does, held back and let through as
//! the BCPs' status reporting delay has it, the transition counters, the messages, and
//! the lost and late packet counters or the transmission error counters.
//!
//! What it measures:
//!
//! - **link**: whether the interfaces the stream uses are up;
//! - **connection** (a Receiver's): whether every packet of the stream arrives, from
//!   what `st2110 receive` counts every half second: none for half a second, or any
//!   lost or too late after merging, is unhealthy; a leg's loss the other made good, or
//!   a leg that brings nothing, is partly healthy;
//! - **transmission** (a Sender's): whether every packet goes out: any the system had
//!   no room for, or nothing sent for half a second, is unhealthy; any more than 100 µs
//!   late is partly healthy;
//! - **synchronization**: a Sender that names a PTP grandmaster in its SDP file is
//!   taken as locked to it, as its Node's clock is, since the system clock is said to
//!   follow it (this program does not check); otherwise it is not used, the source
//!   `internal`;
//! - **stream** (a Receiver's): whether what arrives is the stream the SDP file
//!   describes; **essence** (a Sender's) is always healthy, since a Sender of this
//!   program always has its test pattern or tone to send.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use st2110_media::net::TransmitCounts;
use st2110_media::receive::Report;
use st2110_nmos::ncp::{ElementId, property as p};

use super::connection::Side;

const INACTIVE: u64 = 0;
const HEALTHY: u64 = 1;
const PARTIAL: u64 = 2;
const UNHEALTHY: u64 = 3;

/// The default status reporting delay, in seconds (BCP-008-01: "Devices MUST use 3s as
/// the default value").
pub(crate) const DEFAULT_DELAY: u64 = 3;

/// The longest status reporting delay a controller may set, in seconds.
pub(crate) const MOST_DELAY: u64 = 3600;

/// How long a Receiver may go without a count from the receiving before it is taken as
/// receiving nothing.
const STALE: Duration = Duration::from_millis(1500);

/// The four domains, in property order: link, connection or transmission,
/// synchronization, stream or essence.
const LINK: usize = 0;
const CONNECTION: usize = 1;
const SYNC: usize = 2;
const STREAM: usize = 3;

/// The status, message and transition counter properties of each domain.
const DOMAINS: [(ElementId, ElementId, ElementId); 4] = [
    (p::LINK_STATUS, p::LINK_STATUS_MESSAGE, p::LINK_STATUS_TRANSITION_COUNTER),
    (p::CONNECTION_STATUS, p::CONNECTION_STATUS_MESSAGE, p::CONNECTION_STATUS_TRANSITION_COUNTER),
    (p::SYNCHRONIZATION_STATUS, p::SYNCHRONIZATION_STATUS_MESSAGE, p::SYNCHRONIZATION_STATUS_TRANSITION_COUNTER),
    (p::STREAM_STATUS, p::STREAM_STATUS_MESSAGE, p::STREAM_STATUS_TRANSITION_COUNTER),
];

/// A status as measured: its value and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Measured {
    pub status: u64,
    pub message: Option<String>,
}

impl Measured {
    fn healthy() -> Self {
        Self { status: HEALTHY, message: None }
    }

    fn bad(status: u64, message: impl Into<String>) -> Self {
        Self { status, message: Some(message.into()) }
    }

    /// The link's status, from the addresses of the stream's interfaces that are no
    /// longer on any interface, of `of`.
    pub(crate) fn link(down: &[String], of: usize) -> Self {
        match down {
            [] => Self::healthy(),
            _ if down.len() >= of => Self::bad(UNHEALTHY, format!("no interface has {} now", down.join(" or "))),
            _ => Self::bad(PARTIAL, format!("no interface has {} now; the others are up", down.join(" or "))),
        }
    }
}

/// A count the monitor keeps, such as lost packets: `kind` is `lost`, `late` or
/// `errors`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Count {
    pub kind: &'static str,
    pub name: String,
    pub description: &'static str,
    /// Since the receiving or sending started.
    pub value: u64,
}

/// What the stream did lately, for the monitor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observation {
    /// The connection or transmission status measured.
    pub connection: Option<Measured>,
    /// The stream status measured; `None` keeps the last.
    pub stream: Option<Measured>,
    /// The counts so far.
    pub counts: Vec<Count>,
    /// Which receiving or sending the counts belong to: counts start again at 0 with a
    /// new one.
    pub generation: u64,
}

/// One domain's status as reported.
#[derive(Debug)]
struct Domain {
    reported: u64,
    /// Whether its status has a neutral value (`Inactive`, `NotUsed`), 0.
    neutral: bool,
    /// The healthier status measured, and since when, waiting out the delay.
    pending: Option<(u64, Instant)>,
    /// The message of the last unhealthy status, for "Previously: ".
    last_bad: Option<String>,
}

/// A counter, kept across receivings and resets.
#[derive(Debug, Default)]
struct Counter {
    description: &'static str,
    /// What earlier receivings counted, since the last reset.
    carried: u64,
    /// The value at the last reset, in this receiving.
    base: u64,
    last: u64,
    generation: u64,
}

impl Counter {
    fn value(&self) -> u64 {
        self.carried + self.last.saturating_sub(self.base)
    }
}

/// The monitor.
#[derive(Debug)]
pub(crate) struct Monitor {
    side: Side,
    /// Its property values, by id: those of NcObject and NcWorker too.
    values: BTreeMap<ElementId, Value>,
    domains: [Domain; 4],
    measured: [Measured; 4],
    active: bool,
    activated_at: Option<Instant>,
    /// When the stream was last counted.
    observed_at: Instant,
    counters: BTreeMap<(&'static str, String), Counter>,
    /// The properties that changed, to tell subscribers of.
    changes: Vec<(ElementId, Value)>,
}

/// What a Device of this program knows of its synchronization.
#[derive(Clone, Debug)]
pub(crate) struct Sync {
    pub measured: Measured,
    pub source: Option<String>,
}

impl Sync {
    /// Locked, as taken, to `grandmaster`.
    pub(crate) fn ptp(grandmaster: &str, domain: Option<u8>) -> Self {
        let source = match domain {
            Some(domain) => format!("{grandmaster} (PTP domain {domain})"),
            None => grandmaster.to_string(),
        };
        Self {
            measured: Measured::bad(
                HEALTHY,
                "taken as locked: the system clock is said to follow this grandmaster, which st2110 does not check",
            ),
            source: Some(source),
        }
    }

    /// No external synchronization: the machine's own clock.
    pub(crate) fn internal() -> Self {
        Self { measured: Measured { status: 0, message: None }, source: Some("internal".into()) }
    }
}

impl Monitor {
    /// A monitor of `side`, active or not, with these values for its NcObject
    /// properties (role, label, touchpoints and the rest).
    pub(crate) fn new(side: Side, object: BTreeMap<ElementId, Value>, sync: &Sync, active: bool, now: Instant) -> Self {
        let neutral = [false, true, true, true];
        let domains = std::array::from_fn(|i| Domain {
            reported: if i == LINK { HEALTHY } else { 0 },
            neutral: neutral[i],
            pending: None,
            last_bad: None,
        });
        let mut measured: [Measured; 4] = std::array::from_fn(|_| Measured::healthy());
        measured[SYNC] = sync.measured.clone();
        let mut values = object;
        values.insert(p::ENABLED, json!(true));
        values.insert(p::OVERALL_STATUS, json!(INACTIVE));
        values.insert(p::OVERALL_STATUS_MESSAGE, Value::Null);
        values.insert(p::STATUS_REPORTING_DELAY, json!(DEFAULT_DELAY));
        for (i, (status, message, counter)) in DOMAINS.iter().enumerate() {
            values.insert(*status, json!(domains[i].reported));
            values.insert(*message, Value::Null);
            values.insert(*counter, json!(0));
        }
        values.insert(p::SYNCHRONIZATION_SOURCE_ID, json!(sync.source));
        values.insert(p::AUTO_RESET, json!(true));
        let mut counters = BTreeMap::new();
        let first: &[(&str, &str, &str)] = match side {
            Side::Receiver => &[
                ("lost", "lost", "Packets no leg delivered, after merging the legs"),
                ("late", "late", "Packets that came after the receiver had stopped waiting for them"),
            ],
            Side::Sender => &[
                ("errors", "late", "Packets that went out more than 100 µs after their time"),
                ("errors", "refused", "Packets the operating system did not take, for want of buffer space"),
            ],
        };
        for (kind, name, description) in first {
            counters.insert((*kind, (*name).to_string()), Counter { description, ..Counter::default() });
        }
        let mut monitor = Self {
            side,
            values,
            domains,
            measured,
            active: false,
            activated_at: None,
            observed_at: now,
            counters,
            changes: Vec::new(),
        };
        monitor.activate(active, now);
        monitor.update(now);
        monitor.changes.clear();
        monitor
    }

    /// A property's value.
    pub(crate) fn get(&self, id: ElementId) -> Option<&Value> {
        self.values.get(&id)
    }

    fn set(&mut self, id: ElementId, value: Value) {
        if self.values.get(&id) != Some(&value) {
            self.values.insert(id, value.clone());
            self.changes.push((id, value));
        }
    }

    /// The properties that changed since this was last asked.
    pub(crate) fn take_changes(&mut self) -> Vec<(ElementId, Value)> {
        std::mem::take(&mut self.changes)
    }

    pub(crate) fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    fn delay(&self) -> Duration {
        Duration::from_secs(
            self.values.get(&p::STATUS_REPORTING_DELAY).and_then(Value::as_u64).unwrap_or(DEFAULT_DELAY),
        )
    }

    /// Sets the user label.
    pub(crate) fn set_label(&mut self, label: Value) {
        self.set(p::USER_LABEL, label);
    }

    /// Sets the status reporting delay, in seconds.
    pub(crate) fn set_delay(&mut self, seconds: u64, now: Instant) {
        self.set(p::STATUS_REPORTING_DELAY, json!(seconds));
        self.update(now);
    }

    /// Sets whether an activation resets the counters and messages.
    pub(crate) fn set_auto_reset(&mut self, on: bool) {
        self.set(p::AUTO_RESET, json!(on));
    }

    /// An IS-05 activation: `enabled` is the new `master_enable`. An activation that
    /// leaves the Receiver or Sender on is one too (BCP-008-01 Definitions).
    pub(crate) fn activate(&mut self, enabled: bool, now: Instant) {
        if enabled {
            self.active = true;
            self.activated_at = Some(now);
            self.observed_at = now;
            if self.values.get(&p::AUTO_RESET) != Some(&json!(false)) {
                self.reset();
            }
            // Statuses that can be Inactive go to Healthy at once.
            for i in [CONNECTION, STREAM] {
                self.domains[i].reported = HEALTHY;
                self.domains[i].pending = None;
                self.measured[i] = Measured::healthy();
            }
        } else {
            // Deactivated: straight to Inactive, with no unhealthy step between.
            self.active = false;
            self.activated_at = None;
            for i in [CONNECTION, STREAM] {
                self.domains[i].reported = INACTIVE;
                self.domains[i].pending = None;
            }
        }
        self.publish();
    }

    /// ResetCountersAndMessages: every transition counter, packet counter and status
    /// message back to nothing.
    pub(crate) fn reset(&mut self) {
        for counter in self.counters.values_mut() {
            counter.carried = 0;
            counter.base = counter.last;
        }
        for domain in &mut self.domains {
            domain.last_bad = None;
        }
        for (_, message, counter) in DOMAINS {
            self.set(message, Value::Null);
            self.set(counter, json!(0));
        }
        self.set(p::OVERALL_STATUS_MESSAGE, Value::Null);
    }

    /// The counters of one kind, as `NcCounter`s.
    pub(crate) fn counters(&self, kind: &str) -> Vec<Value> {
        self.counters
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|((_, name), c)| json!({"name": name, "value": c.value(), "description": c.description}))
            .collect()
    }

    /// The link's status, measured.
    pub(crate) fn measure_link(&mut self, measured: Measured) {
        self.measured[LINK] = measured;
    }

    /// What the stream did lately.
    pub(crate) fn observe(&mut self, observation: Observation, now: Instant) {
        self.observed_at = now;
        if let Some(connection) = observation.connection {
            self.measured[CONNECTION] = connection;
        }
        if let Some(stream) = observation.stream {
            self.measured[STREAM] = stream;
        }
        for count in observation.counts {
            let counter = self.counters.entry((count.kind, count.name)).or_default();
            counter.description = count.description;
            if counter.generation != observation.generation {
                counter.carried = counter.value();
                counter.base = 0;
                counter.generation = observation.generation;
            }
            counter.last = count.value;
        }
    }

    /// Reports what has been measured, as the status reporting delay lets it through.
    pub(crate) fn update(&mut self, now: Instant) {
        if self.active && self.side == Side::Receiver && now.duration_since(self.observed_at) > STALE {
            self.measured[CONNECTION] = Measured::bad(UNHEALTHY, "nothing is being received");
        }
        let delay = self.delay();
        let holding = self.activated_at.is_some_and(|at| now < at + delay);
        for i in 0..DOMAINS.len() {
            let target = if !self.active && (i == CONNECTION || i == STREAM) {
                Measured { status: INACTIVE, message: None }
            } else {
                self.measured[i].clone()
            };
            self.report(i, target, holding, delay, now);
        }
        self.publish();
    }

    /// Moves one domain toward `target`: less healthy at once, but not while the
    /// activation's delay runs; healthier only once it has lasted the delay; to or from
    /// a neutral status at once.
    fn report(&mut self, i: usize, target: Measured, holding: bool, delay: Duration, now: Instant) {
        let (status_id, message_id, counter_id) = DOMAINS[i];
        let domain = &mut self.domains[i];
        let from = domain.reported;
        let has_neutral = domain.neutral;
        let neutral = |s: u64| has_neutral && s == 0;
        if target.status == from {
            domain.pending = None;
            if from > HEALTHY && target.message.is_some() {
                domain.last_bad.clone_from(&target.message);
                self.set(message_id, json!(target.message));
            }
            return;
        }
        let worse = !neutral(from) && !neutral(target.status) && target.status > from;
        let better = !neutral(from) && !neutral(target.status) && target.status < from;
        if worse {
            if holding {
                return;
            }
            domain.pending = None;
        } else if better && !delay.is_zero() && !holding {
            match domain.pending {
                Some((status, since)) if status == target.status => {
                    if now.duration_since(since) < delay {
                        return;
                    }
                }
                _ => {
                    domain.pending = Some((target.status, now));
                    return;
                }
            }
            domain.pending = None;
        } else {
            domain.pending = None;
        }
        domain.reported = target.status;
        let message = if target.status > HEALTHY {
            domain.last_bad.clone_from(&target.message);
            target.message
        } else if target.status == HEALTHY && from > HEALTHY {
            domain.last_bad.as_ref().map(|m| format!("Previously: {m}")).or(target.message)
        } else {
            target.message.or_else(|| self.values.get(&message_id).and_then(|m| m.as_str().map(String::from)))
        };
        let count = self.values.get(&counter_id).and_then(Value::as_u64).unwrap_or(0) + u64::from(worse);
        self.set(status_id, json!(target.status));
        self.set(message_id, json!(message));
        self.set(counter_id, json!(count));
    }

    /// Sets the overall status from the domains: Inactive while inactive, otherwise the
    /// least healthy of them, neutral ones aside.
    fn publish(&mut self) {
        for (i, (status, _, _)) in DOMAINS.iter().enumerate() {
            let reported = self.domains[i].reported;
            self.set(*status, json!(reported));
        }
        let was = self.values.get(&p::OVERALL_STATUS).and_then(Value::as_u64).unwrap_or(INACTIVE);
        let overall = if self.active {
            self.domains.iter().filter(|d| !(d.neutral && d.reported == 0)).map(|d| d.reported).max().unwrap_or(HEALTHY)
        } else {
            INACTIVE
        };
        let message = if overall > HEALTHY {
            let causes: Vec<String> = DOMAINS
                .iter()
                .enumerate()
                .filter(|(i, _)| self.domains[*i].reported == overall)
                .filter_map(|(_, (_, message, _))| self.values.get(message)?.as_str().map(String::from))
                .collect();
            (!causes.is_empty()).then(|| causes.join("; "))
        } else if overall == HEALTHY && was > HEALTHY {
            self.values
                .get(&p::OVERALL_STATUS_MESSAGE)
                .and_then(Value::as_str)
                .map(|m| if m.starts_with("Previously: ") { m.to_string() } else { format!("Previously: {m}") })
        } else {
            self.values.get(&p::OVERALL_STATUS_MESSAGE).and_then(Value::as_str).map(String::from)
        };
        self.set(p::OVERALL_STATUS, json!(overall));
        self.set(p::OVERALL_STATUS_MESSAGE, json!(message));
    }
}

/// Measures a Receiver's connection and stream from what `st2110 receive` counted:
/// what changed since the last count.
#[derive(Debug, Default)]
pub(crate) struct ReceiverMeter {
    generation: u64,
    last: Option<Totals>,
}

#[derive(Clone, Debug, Default)]
struct Totals {
    passed: u64,
    lost: u64,
    late: u64,
    datagrams: Vec<u64>,
    leg_lost: Vec<u64>,
    leg_late: Vec<u64>,
    /// Datagrams left out: from another source, of another payload type, not RTP, or
    /// fitting neither the stream nor a restart.
    others: u64,
}

impl Totals {
    fn of(report: &Report) -> Self {
        Self {
            passed: report.passed,
            lost: report.lost,
            late: report.too_late,
            datagrams: report.legs.iter().map(|l| l.datagrams).collect(),
            leg_lost: report.legs.iter().map(|l| l.rtp.lost).collect(),
            leg_late: report.legs.iter().map(|l| l.rtp.too_late).collect(),
            others: report.strays
                + report.legs.iter().map(|l| l.other_source + l.other_payload_type + l.not_rtp).sum::<u64>(),
        }
    }
}

impl ReceiverMeter {
    /// A new receiving starts: its counts start from 0.
    pub(crate) fn start(&mut self) {
        self.generation += 1;
        self.last = None;
    }

    /// What `report`, the receiving's counts so far, says since the last.
    pub(crate) fn observe(&mut self, report: &Report) -> Observation {
        let now = Totals::of(report);
        let before = self.last.replace(now.clone()).unwrap_or_else(|| Totals {
            datagrams: vec![0; now.datagrams.len()],
            leg_lost: vec![0; now.leg_lost.len()],
            leg_late: vec![0; now.leg_late.len()],
            ..Totals::default()
        });
        let delta = |a: u64, b: u64| a.saturating_sub(b);
        let legs = |a: &[u64], b: &[u64]| -> Vec<u64> {
            a.iter().enumerate().map(|(i, n)| delta(*n, b.get(i).copied().unwrap_or(0))).collect()
        };
        let passed = delta(now.passed, before.passed);
        let datagrams = legs(&now.datagrams, &before.datagrams);
        let arrived: u64 = datagrams.iter().sum();
        let leg_lost: u64 = legs(&now.leg_lost, &before.leg_lost).iter().sum();
        let (lost, late) = (delta(now.lost, before.lost), delta(now.late, before.late));
        let others = delta(now.others, before.others);
        let silent: Vec<String> =
            datagrams.iter().enumerate().filter(|(_, n)| **n == 0).map(|(i, _)| format!("leg {}", i + 1)).collect();
        let connection = if arrived == 0 {
            Measured::bad(UNHEALTHY, "no packets arrive")
        } else if passed == 0 {
            Measured::bad(UNHEALTHY, "none of the packets that arrive are the stream's")
        } else if lost > 0 && late > 0 {
            Measured::bad(UNHEALTHY, "packets are lost, and others come too late")
        } else if lost > 0 {
            Measured::bad(UNHEALTHY, "packets are lost")
        } else if late > 0 {
            Measured::bad(UNHEALTHY, "packets come too late")
        } else if !silent.is_empty() {
            Measured::bad(PARTIAL, format!("{} brings nothing; the other leg carries the stream", silent.join(", ")))
        } else if leg_lost > 0 {
            Measured::bad(PARTIAL, "a leg loses packets, and the other leg makes them good")
        } else {
            Measured::healthy()
        };
        let stream = if arrived == 0 {
            None
        } else if passed == 0 {
            Some(Measured::bad(UNHEALTHY, "what arrives is not the stream the SDP file describes"))
        } else if others > 0 {
            Some(Measured::bad(PARTIAL, "packets that are not the stream's arrive with it"))
        } else {
            Some(Measured::healthy())
        };
        let mut counts = vec![
            Count {
                kind: "lost",
                name: "lost".into(),
                description: "Packets no leg delivered, after merging the legs",
                value: now.lost,
            },
            Count {
                kind: "late",
                name: "late".into(),
                description: "Packets that came after the receiver had stopped waiting for them",
                value: now.late,
            },
        ];
        if now.leg_lost.len() > 1 {
            for (i, (lost, late)) in now.leg_lost.iter().zip(&now.leg_late).enumerate() {
                counts.push(Count {
                    kind: "lost",
                    name: format!("leg {} lost", i + 1),
                    description: "Packets this leg did not deliver: gaps in its own sequence numbers",
                    value: *lost,
                });
                counts.push(Count {
                    kind: "late",
                    name: format!("leg {} late", i + 1),
                    description: "Packets that came on this leg too far behind the others to be merged",
                    value: *late,
                });
            }
        }
        Observation { connection: Some(connection), stream, counts, generation: self.generation }
    }
}

/// Measures a Sender's transmission from how its sockets kept time.
#[derive(Debug, Default)]
pub(crate) struct SenderMeter {
    last: Option<TransmitCounts>,
}

impl SenderMeter {
    pub(crate) fn observe(&mut self, now: TransmitCounts) -> Observation {
        let before = self.last.replace(now).unwrap_or_default();
        let sent = now.sent.saturating_sub(before.sent);
        let late = now.late.saturating_sub(before.late);
        let refused = now.refused.saturating_sub(before.refused);
        let connection = if refused > 0 {
            Measured::bad(UNHEALTHY, "the system's buffers have no room for some packets, so they are not sent")
        } else if sent == 0 {
            Measured::bad(UNHEALTHY, "nothing is sent")
        } else if late > 0 {
            Measured::bad(PARTIAL, "packets go out more than 100 µs after their time")
        } else {
            Measured::healthy()
        };
        let counts = vec![
            Count {
                kind: "errors",
                name: "late".into(),
                description: "Packets that went out more than 100 µs after their time",
                value: now.late,
            },
            Count {
                kind: "errors",
                name: "refused".into(),
                description: "Packets the operating system did not take, for want of buffer space",
                value: now.refused,
            },
        ];
        Observation { connection: Some(connection), stream: Some(Measured::healthy()), counts, generation: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(side: Side, active: bool, at: Instant) -> Monitor {
        Monitor::new(side, BTreeMap::new(), &Sync::internal(), active, at)
    }

    fn status(m: &Monitor, id: ElementId) -> u64 {
        m.get(id).and_then(Value::as_u64).unwrap()
    }

    fn message(m: &Monitor, id: ElementId) -> Option<&str> {
        m.get(id).and_then(Value::as_str)
    }

    fn lost(m: &mut Monitor, at: Instant) {
        m.observe(
            Observation {
                connection: Some(Measured::bad(UNHEALTHY, "packets are lost")),
                stream: None,
                counts: vec![Count { kind: "lost", name: "lost".into(), description: "", value: 5 }],
                generation: 1,
            },
            at,
        );
        m.update(at);
    }

    fn fine(m: &mut Monitor, at: Instant) {
        m.observe(Observation { connection: Some(Measured::healthy()), generation: 1, ..Observation::default() }, at);
        m.update(at);
    }

    #[test]
    fn holds_back_and_lets_through_as_bcp_008_has_it() {
        let t0 = Instant::now();
        let s = |n: f64| t0 + Duration::from_secs_f64(n);
        let mut m = monitor(Side::Receiver, false, t0);
        assert_eq!(status(&m, p::OVERALL_STATUS), INACTIVE);
        assert_eq!(status(&m, p::CONNECTION_STATUS), INACTIVE);
        assert_eq!(status(&m, p::LINK_STATUS), HEALTHY);
        assert_eq!(status(&m, p::SYNCHRONIZATION_STATUS), 0);
        assert_eq!(m.get(p::SYNCHRONIZATION_SOURCE_ID), Some(&json!("internal")));

        // Activated: Healthy at once, and loss in the first 3 s is not reported.
        m.activate(true, s(1.0));
        assert_eq!(status(&m, p::CONNECTION_STATUS), HEALTHY);
        assert_eq!(status(&m, p::OVERALL_STATUS), HEALTHY);
        let changed: Vec<ElementId> = m.take_changes().into_iter().map(|(id, _)| id).collect();
        assert!(changed.contains(&p::OVERALL_STATUS) && changed.contains(&p::CONNECTION_STATUS), "{changed:?}");
        lost(&mut m, s(2.0));
        assert_eq!(status(&m, p::CONNECTION_STATUS), HEALTHY);
        // After it, at once, counted, with the overall status and its message.
        lost(&mut m, s(4.5));
        assert_eq!(status(&m, p::CONNECTION_STATUS), UNHEALTHY);
        assert_eq!(status(&m, p::CONNECTION_STATUS_TRANSITION_COUNTER), 1);
        assert_eq!(status(&m, p::OVERALL_STATUS), UNHEALTHY);
        assert_eq!(message(&m, p::OVERALL_STATUS_MESSAGE), Some("packets are lost"));
        assert_eq!(m.counters("lost")[0]["value"], 5);
        // Healthier only once that has lasted 3 s, then "Previously: ".
        fine(&mut m, s(5.0));
        fine(&mut m, s(7.0));
        assert_eq!(status(&m, p::CONNECTION_STATUS), UNHEALTHY);
        fine(&mut m, s(8.1));
        assert_eq!(status(&m, p::CONNECTION_STATUS), HEALTHY);
        assert_eq!(message(&m, p::CONNECTION_STATUS_MESSAGE), Some("Previously: packets are lost"));
        assert_eq!(message(&m, p::OVERALL_STATUS_MESSAGE), Some("Previously: packets are lost"));
        // Silence for longer than the counts come is nothing received.
        m.update(s(10.0));
        assert_eq!(status(&m, p::CONNECTION_STATUS), UNHEALTHY);
        assert_eq!(message(&m, p::CONNECTION_STATUS_MESSAGE), Some("nothing is being received"));
        assert_eq!(status(&m, p::CONNECTION_STATUS_TRANSITION_COUNTER), 2);

        // Deactivated: Inactive at once, no step between.
        m.take_changes();
        m.activate(false, s(10.5));
        assert_eq!(status(&m, p::CONNECTION_STATUS), INACTIVE);
        assert_eq!(status(&m, p::STREAM_STATUS), INACTIVE);
        assert_eq!(status(&m, p::OVERALL_STATUS), INACTIVE);
        assert_eq!(status(&m, p::CONNECTION_STATUS_TRANSITION_COUNTER), 2);
        // Activated again: counters and messages reset, as autoResetCountersAndMessages has it.
        m.activate(true, s(11.0));
        assert_eq!(status(&m, p::CONNECTION_STATUS_TRANSITION_COUNTER), 0);
        assert_eq!(m.get(p::CONNECTION_STATUS_MESSAGE), Some(&Value::Null));
        assert_eq!(m.counters("lost")[0]["value"], 0);
    }

    #[test]
    fn no_delay_reports_at_once_and_counters_survive_without_auto_reset() {
        let t0 = Instant::now();
        let mut m = monitor(Side::Receiver, true, t0);
        m.set_delay(0, t0);
        m.set_auto_reset(false);
        lost(&mut m, t0);
        assert_eq!(status(&m, p::CONNECTION_STATUS), UNHEALTHY);
        fine(&mut m, t0);
        assert_eq!(status(&m, p::CONNECTION_STATUS), HEALTHY);
        m.activate(true, t0);
        assert_eq!(m.counters("lost")[0]["value"], 5);
        // A new receiving counts from 0 again, and adds to what was counted.
        m.observe(
            Observation {
                counts: vec![Count { kind: "lost", name: "lost".into(), description: "", value: 2 }],
                generation: 2,
                ..Observation::default()
            },
            t0,
        );
        assert_eq!(m.counters("lost")[0]["value"], 7);
        m.reset();
        assert_eq!(m.counters("lost")[0]["value"], 0);
        assert_eq!(m.counters("late")[0]["value"], 0);
    }

    #[test]
    fn meters_read_what_changed() {
        let mut meter = ReceiverMeter::default();
        meter.start();
        let mut report = Report { legs: vec![Default::default(), Default::default()], ..Default::default() };
        let seen = meter.observe(&report);
        assert_eq!(seen.connection.unwrap().message.as_deref(), Some("no packets arrive"));
        assert_eq!(seen.stream, None);
        report.passed = 100;
        report.legs[0].datagrams = 100;
        let seen = meter.observe(&report);
        assert_eq!(seen.connection.unwrap().status, PARTIAL);
        assert_eq!(seen.counts.len(), 6);
        report.passed = 200;
        report.legs[0].datagrams = 200;
        report.legs[1].datagrams = 100;
        report.lost = 3;
        let seen = meter.observe(&report);
        assert_eq!(seen.connection.unwrap().message.as_deref(), Some("packets are lost"));
        assert_eq!(seen.stream.unwrap().status, HEALTHY);

        let mut meter = SenderMeter::default();
        let counts = |sent, late, refused| TransmitCounts { sent, late, latest_ns: 0, refused };
        assert_eq!(meter.observe(counts(10, 0, 0)).connection.unwrap().status, HEALTHY);
        assert_eq!(meter.observe(counts(20, 1, 0)).connection.unwrap().status, PARTIAL);
        assert_eq!(meter.observe(counts(20, 1, 0)).connection.unwrap().message.as_deref(), Some("nothing is sent"));
        assert_eq!(meter.observe(counts(30, 1, 2)).connection.unwrap().status, UNHEALTHY);
    }
}
