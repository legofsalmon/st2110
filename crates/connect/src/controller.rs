//! Makes connections through IS-05 the way a controller does: finds each Receiver and the
//! stream it is to take in a registry snapshot, plans the change against the Receiver's
//! constraints, sends it to the Receiver's Connection API, and checks that it took, on
//! the Connection API and in the registry.
//!
//! Connections asked for together are made together, as a salvo: when one is refused,
//! none is sent. By default they take effect at one PTP time a little after they are
//! sent, so that every Receiver switches at once, and when a Connection API rejects its
//! part or does not answer, the others are cancelled, or put back as their `/active`
//! endpoints showed them (IS-05 v1.2 Behaviour: Scheduled Activations).
//!
//! ```no_run
//! use st2110_connect::client::{ConnectionClient, Options};
//! use st2110_connect::controller::{Route, Settings, Take, connect};
//! use st2110_nmos::client::{self, QueryClient};
//!
//! // Only the resources: each Sender's SDP file is read when it is needed.
//! let read = client::Options { fetch_sdp: false, ..client::Options::default() };
//! let registry = QueryClient::connect("http://registry.example:8080", &read)?;
//! let snapshot = registry.snapshot()?;
//! let routes = [
//!     Route { receiver: "MON 1 video".into(), take: Take::Sender("CAM 2 video".into()) },
//!     Route { receiver: "MON 1 audio".into(), take: Take::Sender("CAM 2 audio".into()) },
//! ];
//! let client = ConnectionClient::new(&Options::default());
//! let outcome = connect(&snapshot, &routes, &client, Some(&registry), &Settings::default())?;
//! for connection in &outcome.connections {
//!     println!("{}: {}", connection.receiver.describe(), connection.state.describe());
//! }
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};
use st2110_nmos::client::QueryClient;
use st2110_nmos::routing::{self, Endpoint};
use st2110_nmos::{Kind, Snapshot};
use st2110_ptp::{PtpTime, TAI_UTC_2017};

use crate::client::{ConnectionClient, Reply, bulk, single};
use crate::{Activation, Constraints, Plan, tai};

/// Receivers to read at once while connections are prepared.
const AT_ONCE: usize = 16;

/// The least time a request is given to be answered, however close its salvo is to
/// being due.
const LEAST: Duration = Duration::from_millis(100);

/// How often a Receiver's `/active` endpoint, and the registry, are read again while a
/// change is awaited.
const POLL: Duration = Duration::from_millis(200);

/// What a Receiver is to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Take {
    /// The stream of the Sender this names: its `id`, its `label` or the start of its `id`.
    Sender(String),
    /// The stream an SDP file describes, such as one from outside NMOS.
    Sdp {
        /// Where the file came from, for messages.
        name: String,
        /// The file.
        text: String,
    },
    /// Nothing: the Receiver is disconnected.
    Nothing,
}

/// A connection to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The Receiver: its `id`, its `label` or the start of its `id`.
    pub receiver: String,
    /// What it is to take.
    pub take: Take,
}

/// How [`connect`] makes connections.
#[derive(Clone, Debug)]
pub struct Settings {
    /// When the connections take effect. `None` picks: at once for one Receiver, and
    /// [`Settings::lead`] after they are sent for several, so that they switch together.
    pub activation: Option<Activation>,
    /// How far ahead a salvo is scheduled: time enough for every Connection API to have
    /// its request before it is due.
    pub lead: Duration,
    /// Whether to send connections the checks found problems with. The Connection API
    /// may still refuse them.
    pub force: bool,
    /// Whether to plan and check without sending anything.
    pub dry_run: bool,
    /// How long to wait for a Receiver's `/active` endpoint, and then the registry, to
    /// show a change; a scheduled activation due later than this is not awaited.
    pub wait: Duration,
    /// TAI − UTC in seconds, to turn the system clock into PTP time.
    pub tai_utc: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            activation: None,
            lead: Duration::from_secs(2),
            force: false,
            dry_run: false,
            wait: Duration::from_secs(5),
            tai_utc: TAI_UTC_2017,
        }
    }
}

/// What became of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Planned and checked, and not sent: a dry run.
    Planned,
    /// Not sent: the checks found problems, or it cannot be made at all.
    Refused,
    /// Not sent, because another connection in the salvo was refused.
    Held,
    /// Sent, and the Connection API rejected it or did not answer.
    Failed,
    /// Accepted, then cancelled or put back because another connection in the salvo failed.
    RolledBack,
    /// Accepted, and not undone when another connection in the salvo failed: the
    /// Receiver may be left connected.
    RollbackFailed,
    /// Accepted, to take effect later than the controller waits for.
    Scheduled,
    /// Took effect, and the Receiver's `/active` endpoint shows it.
    Done,
    /// Took effect, but the Receiver's `/active` endpoint shows something else.
    Differs,
}

impl State {
    /// A word or two for the state, such as `rolled back`.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Refused => "refused",
            Self::Held => "held back",
            Self::Failed => "failed",
            Self::RolledBack => "rolled back",
            Self::RollbackFailed => "rollback failed",
            Self::Scheduled => "scheduled",
            Self::Done => "done",
            Self::Differs => "differs",
        }
    }

    /// Whether the connection was planned, made or scheduled as asked.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Planned | Self::Scheduled | Self::Done)
    }
}

/// One Receiver's connection, and what became of it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Connection {
    /// The Receiver.
    pub receiver: Endpoint,
    /// The Sender whose stream it is to take, when it is to take a registered Sender's.
    pub sender: Option<Endpoint>,
    /// Where the SDP file came from: a URL, or the name of a file.
    pub sdp: Option<String>,
    /// What became of it.
    pub state: State,
    /// The request for the Receiver's `/staged` endpoint, when one was planned.
    pub request: Option<Value>,
    /// When it took effect or is to, in PTP time, as `<seconds>:<nanoseconds>`.
    pub activation_time: Option<String>,
    /// What an operator should know, such as an ST 2022-7 leg left unused.
    pub notes: Vec<String>,
    /// Why it was refused, failed or differs, and the problems it was sent with when
    /// forced.
    pub problems: Vec<String>,
    /// What went wrong without changing the outcome, such as a registry that has not
    /// caught up.
    pub warnings: Vec<String>,
}

impl Connection {
    /// What the Receiver was to take, for messages: `sender "CAM 1 video" (5e0d0001)`,
    /// `the SDP file cam1.sdp` or `nothing`.
    pub fn describe_take(&self) -> String {
        match (&self.sender, &self.sdp) {
            (Some(sender), _) => sender.describe(),
            (None, Some(sdp)) => format!("the SDP file {sdp}"),
            (None, None) => "nothing".into(),
        }
    }
}

/// The connections asked for, and what became of them.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Outcome {
    /// When they were to take effect: the `activation` object sent, or that would have been.
    pub activation: Value,
    /// Each connection, in the order asked for.
    pub connections: Vec<Connection>,
}

impl Outcome {
    /// Whether every connection was planned, made or scheduled as asked.
    pub fn succeeded(&self) -> bool {
        self.connections.iter().all(|c| c.state.is_success())
    }
}

/// A connection being made.
struct Job {
    take: Take,
    report: Connection,
    /// The Receiver's Connection API: its versioned base, ending in `/`.
    api: String,
    /// What the Receiver's `/active` endpoint showed before, to put back when the salvo fails.
    previous: Value,
    plan: Option<Plan>,
    /// Whether it cannot be sent at all, whatever [`Settings::force`] says.
    blocked: bool,
}

/// What a Connection API made of a request.
#[derive(Clone, Debug)]
enum Sent {
    /// Accepted: 200 for an immediate activation, 202 for a scheduled one. A single
    /// `PATCH` returns what was staged. `answered` is when the answer came.
    Accepted { status: u16, staged: Option<Value>, answered: PtpTime },
    /// Refused, with nothing changed: a redirect or a client error.
    Rejected(String),
    /// Not answered, or answered with a server error or without saying: it may or may
    /// not have been acted on.
    Uncertain(String),
}

/// Makes connections, all together: when one cannot be made, none is.
///
/// Each [`Route`] names a Receiver in `snapshot` and what it is to take. For each, the
/// Receiver's `/active` endpoint is read, to put it back should the salvo fail; then for
/// a stream, its `/constraints` and the SDP file, fetched afresh from the Sender's
/// `manifest_href` or else its `/transportfile`. The connection is planned (see
/// [`Plan::connect`]) and checked: against the Receiver's constraints, and against its
/// transport, format and capabilities as the registry lists them ([`routing::route`]).
///
/// When every connection can be made, or [`Settings::force`] is set, they are sent, one
/// request per Connection API: a `PATCH` to `/staged`, or for several Receivers of one
/// API a `POST` to `/bulk/receivers`, falling back to one `PATCH` each when the API
/// has no bulk interface. A salvo scheduled at a time has half the time until then for
/// its requests to be answered. When a Connection API rejects its part, fails or does
/// not answer, the others are rolled back: their activations cancelled, and a Receiver
/// that switched all the same put back, unless another controller has changed it
/// since. Otherwise each is checked on the Receiver's `/active` endpoint once due, and
/// when `registry` is given, on its IS-04 `subscription` and `version`, which the Node
/// must update on every activation.
///
/// Fails, sending nothing, when no route is given, a name finds no Sender or Receiver
/// or more than one, or a Receiver is named twice.
pub fn connect(
    snapshot: &Snapshot,
    routes: &[Route],
    client: &ConnectionClient,
    registry: Option<&QueryClient>,
    settings: &Settings,
) -> Result<Outcome, String> {
    if routes.is_empty() {
        return Err("no connection was asked for".into());
    }
    if now(settings.tai_utc).add_nanos(settings.lead.as_nanos() as i128).is_none() {
        return Err(format!("a lead of {} s reaches past the end of PTP time", settings.lead.as_secs()));
    }
    let mut jobs: Vec<Job> = Vec::with_capacity(routes.len());
    for route in routes {
        let receiver = routing::find(snapshot, Kind::Receiver, &route.receiver)?;
        if jobs.iter().any(|job| job.report.receiver.id.eq_ignore_ascii_case(&receiver.id)) {
            return Err(format!("{} is named twice, but takes one stream at a time", receiver.describe()));
        }
        let sender = match &route.take {
            Take::Sender(name) => Some(routing::find(snapshot, Kind::Sender, name)?),
            _ => None,
        };
        jobs.push(Job {
            take: route.take.clone(),
            report: Connection {
                receiver,
                sender,
                sdp: None,
                state: State::Planned,
                request: None,
                activation_time: None,
                notes: Vec::new(),
                problems: Vec::new(),
                warnings: Vec::new(),
            },
            api: String::new(),
            previous: Value::Null,
            plan: None,
            blocked: false,
        });
    }

    let prepared = each(&jobs, AT_ONCE, |job| prepare(snapshot, client, job));
    for (job, prepared) in jobs.iter_mut().zip(prepared) {
        match prepared {
            Ok(prepared) => {
                job.api = prepared.api;
                job.previous = prepared.previous;
                job.report.sdp = prepared.sdp;
                job.report.problems.extend(prepared.unfit);
                job.report.notes.clone_from(&prepared.plan.notes);
                job.report.problems.extend(prepared.plan.problems.iter().cloned());
                job.plan = Some(prepared.plan);
            }
            Err(problem) => {
                job.report.sdp = match &job.take {
                    Take::Sdp { name, .. } => Some(name.clone()),
                    _ => None,
                };
                job.report.problems.push(problem);
                job.blocked = true;
            }
        }
    }

    let refused = |job: &Job| job.blocked || (!job.report.problems.is_empty() && !settings.force);
    let pick = |jobs: &[Job]| match settings.activation {
        Some(activation) => activation,
        None if jobs.len() == 1 => Activation::Immediate,
        None => Activation::At(now(settings.tai_utc).add_nanos(settings.lead.as_nanos() as i128).unwrap_or_default()),
    };
    if jobs.iter().any(refused) || settings.dry_run {
        let activation = pick(&jobs);
        let any_refused = jobs.iter().any(refused);
        for job in &mut jobs {
            if let Some(plan) = job.plan.take() {
                job.report.request = Some(plan.with_activation(activation).request);
            }
            job.report.state = match (refused(job), any_refused) {
                (true, _) => State::Refused,
                (false, true) => State::Held,
                (false, false) => State::Planned,
            };
        }
        return Ok(Outcome {
            activation: activation.to_json(),
            connections: jobs.into_iter().map(|j| j.report).collect(),
        });
    }

    // The time is picked now, when everything is ready to send.
    let activation = pick(&jobs);
    for job in &mut jobs {
        let plan = job.plan.take().expect("every job that is not refused has a plan").with_activation(activation);
        job.report.request = Some(plan.request.clone());
        job.plan = Some(plan);
    }
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, job) in jobs.iter().enumerate() {
        match groups.iter_mut().find(|(api, _)| *api == job.api) {
            Some((_, members)) => members.push(i),
            None => groups.push((job.api.clone(), vec![i])),
        }
    }
    let sent_at = now(settings.tai_utc);
    // A salvo's requests have half the time before it is due to be answered, leaving the
    // other half to cancel the rest should one be refused or go unanswered.
    let deadline = match activation {
        Activation::At(due) => {
            let half = u64::try_from((due.nanos() - sent_at.nanos()) / 2).unwrap_or(0);
            Instant::now().checked_add(Duration::from_nanos(half))
        }
        _ => None,
    };
    let replies = each(&groups, usize::MAX, |(api, members)| {
        let members: Vec<&Job> = members.iter().map(|&i| &jobs[i]).collect();
        send(client, api, &members, deadline, settings.tai_utc)
    });
    let mut sent: Vec<Option<Sent>> = vec![None; jobs.len()];
    for ((_, members), replies) in groups.iter().zip(replies) {
        for (&i, reply) in members.iter().zip(replies) {
            sent[i] = Some(reply);
        }
    }
    let sent: Vec<Sent> = sent.into_iter().map(|s| s.expect("every job is in a group")).collect();

    let failed = sent.iter().any(|s| !matches!(s, Sent::Accepted { .. }));
    if failed {
        let work: Vec<(&Job, &Sent)> = jobs.iter().zip(&sent).collect();
        let undone = each(&work, usize::MAX, |(job, sent)| roll_back(client, job, sent, activation.is_scheduled()));
        for ((job, sent), (state, warnings)) in jobs.iter_mut().zip(&sent).zip(undone) {
            job.report.warnings.extend(warnings);
            job.report.state = match sent {
                Sent::Accepted { .. } => state,
                Sent::Rejected(problem) | Sent::Uncertain(problem) => {
                    job.report.problems.push(problem.clone());
                    State::Failed
                }
            };
        }
        return Ok(Outcome {
            activation: activation.to_json(),
            connections: jobs.into_iter().map(|j| j.report).collect(),
        });
    }

    let work: Vec<(&Job, &Sent)> = jobs.iter().zip(&sent).collect();
    let settled = each(&work, usize::MAX, |(job, sent)| {
        // Judged on this clock, not the Device's, which may be wrong.
        let due = match activation {
            Activation::Immediate => now(settings.tai_utc),
            Activation::At(time) => time,
            Activation::After(nanos) => sent_at.add_nanos(i128::from(nanos)).unwrap_or(sent_at),
        };
        let staged = match sent {
            Sent::Accepted { staged, .. } => staged.as_ref(),
            _ => None,
        };
        settle(client, registry, job, due, staged, settings)
    });
    for ((job, sent), settled) in jobs.iter_mut().zip(&sent).zip(settled) {
        job.report.state = settled.state;
        job.report.activation_time = settled.activation_time;
        job.report.problems.extend(settled.problems);
        job.report.warnings.extend(settled.warnings);
        // An answer after the time may mean the request came after it too.
        if let (Activation::At(due), Sent::Accepted { answered, .. }) = (activation, sent)
            && *answered > due
        {
            job.report
                .warnings
                .push("its Connection API answered after the time it was due, so it may have switched late".into());
        }
    }
    Ok(Outcome { activation: activation.to_json(), connections: jobs.into_iter().map(|j| j.report).collect() })
}

/// A Receiver's scheduled activation, cancelled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Cancelled {
    /// The Receiver.
    pub receiver: Endpoint,
    /// When the activation that was cancelled was due, in PTP time, as
    /// `<seconds>:<nanoseconds>`; `None` when none was scheduled.
    pub was_due: Option<String>,
    /// Why it could not be cancelled.
    pub problem: Option<String>,
}

/// Cancels a Receiver's scheduled activation, as setting its activation `mode` to null
/// does, which also unlocks its `/staged` endpoint (IS-05 v1.2 ConnectionAPI.raml). What
/// was staged stays staged, and takes effect only when activated again.
///
/// Fails, sending nothing, when the name finds no Receiver or more than one.
pub fn cancel(snapshot: &Snapshot, receiver: &str, client: &ConnectionClient) -> Result<Cancelled, String> {
    let receiver = routing::find(snapshot, Kind::Receiver, receiver)?;
    let attempt = || -> Result<Option<String>, String> {
        let api = connection_api(&receiver)?;
        let url = single(&api, Kind::Receiver, &receiver.id, "staged");
        let staged = read_json(client, &url)?;
        let activation = staged.get("activation");
        let was_due = activation
            .filter(|a| a.get("mode").is_some_and(|mode| !mode.is_null()))
            .and_then(|a| a.get("activation_time")?.as_str())
            .map(str::to_string);
        match client.patch(&url, &json!({"activation": {"mode": null, "requested_time": null}})) {
            Ok(reply) if reply.is_success() => Ok(was_due),
            Ok(reply) => Err(refusal(&reply)),
            Err(e) => Err(format!("no answer: {e}")),
        }
    };
    Ok(match attempt() {
        Ok(was_due) => Cancelled { receiver, was_due, problem: None },
        Err(problem) => Cancelled { receiver, was_due: None, problem: Some(problem) },
    })
}

/// The versioned base of the Connection API that controls a Sender or Receiver.
fn connection_api(endpoint: &Endpoint) -> Result<String, String> {
    endpoint.connection_api.as_ref().map(|api| api.href.clone()).ok_or_else(|| {
        "its Device advertises no IS-05 v1 Connection API (urn:x-nmos:control:sr-ctrl/v1.x) in its controls".into()
    })
}

/// What was read and planned for a connection.
struct Prepared {
    api: String,
    previous: Value,
    plan: Plan,
    sdp: Option<String>,
    /// Why the Receiver cannot take the stream, as the registry lists them.
    unfit: Option<String>,
}

/// Reads what a connection needs and plans it. Fails when it cannot be made at all.
fn prepare(snapshot: &Snapshot, client: &ConnectionClient, job: &Job) -> Result<Prepared, String> {
    let receiver = &job.report.receiver;
    let api = connection_api(receiver)?;
    let previous = read_json(client, &single(&api, Kind::Receiver, &receiver.id, "active"))?;
    let (sdp, from) = match &job.take {
        Take::Nothing => {
            let plan = Plan::disconnect(Activation::Immediate);
            return Ok(Prepared { api, previous, plan, sdp: None, unfit: None });
        }
        Take::Sender(_) => {
            let sender = job.report.sender.as_ref().expect("a Sender route found its Sender");
            sender_sdp(client, sender)?
        }
        Take::Sdp { name, text } => (text.clone(), name.clone()),
    };
    let constraints = read_json(client, &single(&api, Kind::Receiver, &receiver.id, "constraints"))?;
    let constraints = Constraints::from_json(&constraints).map_err(|e| format!("its /constraints are {e}"))?;
    let sender_id = job.report.sender.as_ref().map(|s| s.id.as_str());
    let plan =
        Plan::connect(&sdp, sender_id, &constraints, Activation::Immediate).map_err(|e| format!("{from}: {e}"))?;
    let unfit = match sender_id {
        Some(id) => routing::route(snapshot, id, &receiver.id, Some(&sdp)),
        None => routing::route_sdp(snapshot, &sdp, &receiver.id),
    }
    .err();
    Ok(Prepared { api, previous, plan, sdp: Some(from), unfit })
}

/// A Sender's SDP file, and where it came from: its `manifest_href`, or else its
/// Connection API's `/transportfile`.
fn sender_sdp(client: &ConnectionClient, sender: &Endpoint) -> Result<(String, String), String> {
    let mut urls: Vec<String> = sender.manifest_href.iter().filter(|href| is_http(href)).cloned().collect();
    if let Some(api) = &sender.connection_api {
        let url = single(&api.href, Kind::Sender, &sender.id, "transportfile");
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    if urls.is_empty() {
        return Err(format!(
            "{} publishes no SDP file: it has no manifest_href and its Device advertises no Connection API",
            sender.describe()
        ));
    }
    let mut failures = Vec::new();
    for url in urls {
        match client.transport_file(&url) {
            Ok(Reply { status: 200..=299, body: Value::String(text), .. }) if !text.trim().is_empty() => {
                return Ok((text, url));
            }
            Ok(reply) if reply.is_success() => failures.push(format!("{url} held no SDP file")),
            Ok(reply) => failures.push(format!("{url}: {}", reply.error())),
            Err(e) => failures.push(e.to_string()),
        }
    }
    Err(format!("the SDP file of {} could not be read: {}", sender.describe(), failures.join("; ")))
}

/// Reads a JSON resource that must be there.
fn read_json(client: &ConnectionClient, url: &str) -> Result<Value, String> {
    let reply = client.get(url).map_err(|e| e.to_string())?;
    match reply {
        Reply { status: 200, body: body @ (Value::Object(_) | Value::Array(_)), .. } => Ok(body),
        Reply { status: 200, .. } => Err(format!("{url} returned no JSON")),
        reply => Err(format!("{url}: {}", reply.error())),
    }
}

/// Sends the requests for the Receivers of one Connection API, to be answered by
/// `deadline` when there is one.
fn send(client: &ConnectionClient, api: &str, jobs: &[&Job], deadline: Option<Instant>, tai_utc: i32) -> Vec<Sent> {
    if let [job] = jobs {
        return vec![patch(client, api, job, deadline, tai_utc)];
    }
    let url = bulk(api, Kind::Receiver);
    let body: Vec<Value> = jobs
        .iter()
        .map(|job| json!({"id": job.report.receiver.id, "params": job.plan.as_ref().map(|p| &p.request)}))
        .collect();
    let reply = client.post_within(&url, &Value::Array(body), time_left(deadline));
    let answered = now(tai_utc);
    match reply {
        // No bulk interface: one request each.
        Ok(reply) if matches!(reply.status, 404 | 405 | 501) => {
            each(jobs, usize::MAX, |job| patch(client, api, job, deadline, tai_utc))
        }
        Ok(Reply { status: 200, body: Value::Array(items), .. }) => jobs
            .iter()
            .map(|job| {
                let item = items.iter().find(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| id.eq_ignore_ascii_case(&job.report.receiver.id))
                });
                // Without its result, what became of it is not known.
                let Some(item) = item else {
                    return Sent::Uncertain(format!("the response to {url} says nothing of it"));
                };
                let Some(code) = item.get("code").and_then(Value::as_u64).and_then(|c| u16::try_from(c).ok()) else {
                    return Sent::Uncertain(format!("the response to {url} gives it no code"));
                };
                judge(Reply { status: code, body: item.clone(), location: None }, false, answered)
            })
            .collect(),
        Ok(reply) if reply.is_success() => {
            jobs.iter().map(|_| Sent::Uncertain(format!("{url} returned no list of results"))).collect()
        }
        Ok(reply) => {
            let sent = judge(reply, false, answered);
            jobs.iter().map(|_| sent.clone()).collect()
        }
        Err(e) => jobs.iter().map(|_| Sent::Uncertain(format!("no answer: {e}"))).collect(),
    }
}

/// Sends one Receiver's request to its `/staged` endpoint, to be answered by `deadline`
/// when there is one.
fn patch(client: &ConnectionClient, api: &str, job: &Job, deadline: Option<Instant>, tai_utc: i32) -> Sent {
    let url = single(api, Kind::Receiver, &job.report.receiver.id, "staged");
    let request = &job.plan.as_ref().expect("a job that is sent has a plan").request;
    match client.patch_within(&url, request, time_left(deadline)) {
        Ok(reply) => judge(reply, true, now(tai_utc)),
        Err(e) => Sent::Uncertain(format!("no answer: {e}")),
    }
}

/// What a Connection API's answer says became of a request; `staged` when its body is
/// what was staged.
fn judge(reply: Reply, staged: bool, answered: PtpTime) -> Sent {
    match reply.status {
        200..=299 => Sent::Accepted { status: reply.status, staged: staged.then_some(reply.body), answered },
        300..=499 => Sent::Rejected(refusal(&reply)),
        // A server error may come after the request was acted on.
        _ => Sent::Uncertain(format!("the Connection API failed: {}", reply.error())),
    }
}

/// How long a request may take to be answered by `deadline`.
fn time_left(deadline: Option<Instant>) -> Duration {
    deadline.map_or(Duration::MAX, |deadline| deadline.saturating_duration_since(Instant::now())).max(LEAST)
}

/// Why a Connection API refused a request.
fn refusal(reply: &Reply) -> String {
    let why = match reply.status {
        300..=399 => "; IS-05 redirects only GET requests",
        409 => "; the Connection API serves it at another IS-05 version",
        423 => "; an activation is already scheduled on it",
        _ => "",
    };
    format!("the Connection API refused it: {}{why}", reply.error())
}

/// The `activation_time` in a resource's `activation`.
fn activation_time(resource: &Value) -> Option<PtpTime> {
    PtpTime::parse(resource.get("activation")?.get("activation_time")?.as_str()?)
}

/// Undoes a connection after another in the salvo failed. It cancels what is scheduled,
/// and when the Receiver's `/active` endpoint shows the connection took effect, puts it
/// back as it was; otherwise it stages again what the Receiver had, so that no later
/// activation, from any controller, makes the connection after all. A Receiver that has
/// changed to something else since it was read is left as it is.
fn roll_back(client: &ConnectionClient, job: &Job, sent: &Sent, scheduled: bool) -> (State, Vec<String>) {
    let staged = single(&job.api, Kind::Receiver, &job.report.receiver.id, "staged");
    let plan = job.plan.as_ref().expect("a job that is sent has a plan");
    let mut warnings = Vec::new();
    // Whether an activation may still be pending, to take effect later.
    let mut pending = false;
    // Whether the request may be left staged, for a later activation to make.
    let mut left_staged = false;
    match sent {
        Sent::Rejected(_) => return (State::Failed, warnings),
        // Nothing is pending after an immediate activation.
        Sent::Accepted { status: 200, .. } if !scheduled => {}
        // A scheduled activation, or one that may have been sent.
        Sent::Accepted { .. } | Sent::Uncertain(_) => {
            let cancel = json!({"activation": {"mode": null, "requested_time": null}});
            match client.patch(&staged, &cancel) {
                Ok(reply) if reply.is_success() => left_staged = true,
                Ok(reply) => {
                    pending = true;
                    warnings.push(format!("cancelling its activation was refused: {}", reply.error()));
                }
                Err(e) => {
                    pending = true;
                    warnings.push(format!("cancelling its activation got no answer: {e}"));
                }
            }
        }
    }
    let active = match read_json(client, &single(&job.api, Kind::Receiver, &job.report.receiver.id, "active")) {
        Ok(active) => active,
        Err(e) => {
            warnings.push(format!("whether it changed is not known: {e}"));
            return (State::RollbackFailed, warnings);
        }
    };
    let connection =
        |v: &Value| [v.get("sender_id"), v.get("master_enable"), v.get("transport_params")].map(|f| f.cloned());
    if connection(&active) == connection(&job.previous) {
        if pending {
            // The activation may yet take effect.
            return (State::RollbackFailed, warnings);
        }
        if left_staged {
            let request = Plan::restore(&job.previous, Activation::Immediate).map(|mut restore| {
                restore.request.as_object_mut().map(|request| request.remove("activation"));
                restore.request
            });
            let problem = match request.map(|request| client.patch(&staged, &request)) {
                Ok(Ok(reply)) if reply.is_success() => None,
                Ok(Ok(reply)) => Some(format!("staging what it had again was refused: {}", reply.error())),
                Ok(Err(e)) => Some(format!("staging what it had again got no answer: {e}")),
                Err(e) => Some(e),
            };
            if let Some(problem) = problem {
                warnings.push(format!(
                    "its /staged endpoint may still hold the connection, for a later activation to make: {problem}"
                ));
            }
        }
        return (State::RolledBack, warnings);
    }
    if !plan.verify(&active).is_empty() {
        warnings.push("it has changed since it was read, but not to this connection, so it was left as it is".into());
        return (if pending { State::RollbackFailed } else { State::RolledBack }, warnings);
    }
    let restore = match Plan::restore(&job.previous, Activation::Immediate) {
        Ok(restore) => restore,
        Err(e) => {
            warnings.push(format!("it cannot be put back: {e}"));
            return (State::RollbackFailed, warnings);
        }
    };
    match client.patch(&staged, &restore.request) {
        Ok(reply) if reply.is_success() => {
            warnings.push("it had taken effect, and was put back as it was".into());
            (State::RolledBack, warnings)
        }
        Ok(reply) => {
            warnings.push(format!("putting it back was refused: {}", reply.error()));
            (State::RollbackFailed, warnings)
        }
        Err(e) => {
            warnings.push(format!("putting it back got no answer: {e}"));
            (State::RollbackFailed, warnings)
        }
    }
}

/// What a connection came to once due.
struct Settled {
    state: State,
    activation_time: Option<String>,
    problems: Vec<String>,
    warnings: Vec<String>,
}

/// Waits for an accepted connection to come due, then checks it on the Receiver's
/// `/active` endpoint and in the registry.
fn settle(
    client: &ConnectionClient,
    registry: Option<&QueryClient>,
    job: &Job,
    due: PtpTime,
    staged: Option<&Value>,
    settings: &Settings,
) -> Settled {
    let plan = job.plan.as_ref().expect("a job that is sent has a plan");
    let ahead = due.nanos() - now(settings.tai_utc).nanos();
    if ahead > settings.wait.as_nanos() as i128 {
        // What was staged is all there is to check for now.
        let warnings = staged.map(|s| plan.verify(s)).unwrap_or_default();
        return Settled {
            state: State::Scheduled,
            activation_time: Some(tai(due)),
            problems: Vec::new(),
            warnings: warnings.into_iter().map(|w| format!("it staged something else: {w}")).collect(),
        };
    }
    if ahead > 0 {
        thread::sleep(Duration::from_nanos(u64::try_from(ahead).unwrap_or(u64::MAX)));
    }
    let url = single(&job.api, Kind::Receiver, &job.report.receiver.id, "active");
    let deadline = Instant::now().checked_add(settings.wait);
    let (active, problems) = loop {
        let (active, problems) = match read_json(client, &url) {
            Ok(active) => {
                let problems = plan.verify(&active);
                (Some(active), problems)
            }
            Err(e) => (None, vec![format!("its /active endpoint could not be read: {e}")]),
        };
        if problems.is_empty() || passed(deadline) {
            break (active, problems);
        }
        thread::sleep(POLL);
    };
    // What /active shows is the last activation, which is not this one when it differs.
    let shown = if problems.is_empty() { active.as_ref().and_then(activation_time) } else { None };
    let activation_time = shown.unwrap_or(due);
    let mut settled = Settled {
        state: if problems.is_empty() { State::Done } else { State::Differs },
        activation_time: Some(tai(activation_time)),
        problems: problems.into_iter().map(|p| format!("its /active endpoint shows {p}")).collect(),
        warnings: Vec::new(),
    };
    if settled.state == State::Done
        && let Some(registry) = registry
        && let Some(lag) = registry_lag(registry, job, plan, settings.wait)
    {
        settled.warnings.push(lag);
    }
    settled
}

/// Why the registry does not show a connection that took effect, having waited up to
/// `wait` for it to: IS-05 v1.2 (Interoperability: IS-04) has the Node update the
/// Receiver's `subscription`, and advance its `version`, on every activation.
fn registry_lag(registry: &QueryClient, job: &Job, plan: &Plan, wait: Duration) -> Option<String> {
    let receiver = &job.report.receiver;
    let want = plan.expect.sender_id.as_deref();
    let deadline = Instant::now().checked_add(wait);
    loop {
        let why = match registry.resource(Kind::Receiver, &receiver.id) {
            Ok(Some(resource)) => {
                let subscription = resource.get("subscription");
                let field = |name: &str| subscription.and_then(|s| s.get(name));
                let sender_id = field("sender_id").and_then(Value::as_str);
                let active = field("active").and_then(Value::as_bool);
                let version = resource.get("version").and_then(Value::as_str);
                let same_sender = match (sender_id, want) {
                    (Some(got), Some(want)) => got.eq_ignore_ascii_case(want),
                    (got, want) => got == want,
                };
                let named = |id: Option<&str>| id.map_or_else(|| "no sender".to_string(), |id| format!("sender {id}"));
                let mut subscription = Vec::new();
                if !same_sender {
                    subscription.push(format!("names {} rather than {}", named(sender_id), named(want)));
                }
                if let Some(active) = active
                    && active != plan.expect.master_enable
                {
                    subscription.push(if active { "is active" } else { "is inactive" }.to_string());
                }
                let mut why = Vec::new();
                if !subscription.is_empty() {
                    why.push(format!("its subscription {}", subscription.join(" and ")));
                }
                if let Some(version) = version
                    && receiver.version.as_deref() == Some(version)
                {
                    why.push(format!("its version is still {version}"));
                }
                why.join(", and ")
            }
            Ok(None) => "it is no longer registered".into(),
            Err(e) => format!("it could not be read: {e}"),
        };
        if why.is_empty() {
            return None;
        }
        if passed(deadline) {
            let waited = wait.as_secs_f64();
            return Some(format!(
                "after {waited} s the registry does not show the change: {why}. IS-05 requires the Node to \
                 update the Receiver's subscription and version on every activation"
            ));
        }
        thread::sleep(POLL);
    }
}

/// Whether a deadline has passed; `None` is one too far off to reach.
fn passed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

/// The system clock's time as PTP time, when TAI − UTC is `tai_utc` seconds.
fn now(tai_utc: i32) -> PtpTime {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i128);
    PtpTime::from_utc(unix, tai_utc).unwrap_or_default()
}

fn is_http(href: &str) -> bool {
    let lower = href.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Runs `work` on each item, up to `width` at once, and returns the results in order.
fn each<T: Sync, R: Send>(items: &[T], width: usize, work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() < 2 {
        return items.iter().map(work).collect();
    }
    let chunk = items.len().div_ceil(width.max(1));
    let work = &work;
    thread::scope(|scope| {
        let running: Vec<_> =
            items.chunks(chunk).map(|chunk| scope.spawn(move || chunk.iter().map(work).collect::<Vec<R>>())).collect();
        running
            .into_iter()
            .flat_map(|done| done.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
            .collect()
    })
}
