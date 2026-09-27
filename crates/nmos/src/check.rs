//! The registry checks.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use serde_json::Value;
use st2110_sdp::{ClockIdentity, Rational, RefClock, Stream, parse_frame_rate};

use crate::caps::{self, SdpFacts, StreamFacts};
use crate::model::{Clock, Core, Flow, Kind, Model, Node, Receiver, Sender, Source, is_uuid, short_urn};
use crate::report::{Findings, Grandmaster, ReceiverView, Report, ResourceRef, SenderView, Summary};
use crate::rules::*;
use crate::{Manifest, Snapshot};

/// A Sender's SDP file, linted.
struct Sdp {
    report: st2110_sdp::Report,
    facts: SdpFacts,
}

/// Checks every resource in a snapshot and every SDP file it holds, and lists the
/// Senders and Receivers with their connections.
pub fn check(snapshot: &Snapshot) -> Report {
    let model = Model::read(snapshot);
    let mut findings = Findings::default();
    resources(&model, &mut findings);
    references(&model, &mut findings);
    let (grandmasters, unlocked_clocks) = ptp(&model, &mut findings);
    let sdps: Vec<Option<Sdp>> =
        model.senders.iter().map(|sender| transport_file(&model, snapshot, sender, &mut findings)).collect();
    subscriptions(&model, &sdps, &mut findings);
    connections(&model, &sdps, &mut findings);

    let summary = Summary {
        nodes: model.nodes.len(),
        devices: model.devices.len(),
        sources: model.sources.len(),
        flows: model.flows.len(),
        senders: model.senders.len(),
        receivers: model.receivers.len(),
        active_senders: model.senders.iter().filter(|s| s.active() == Some(true)).count(),
        active_receivers: model.receivers.iter().filter(|r| r.active()).count(),
        grandmasters,
        unlocked_clocks,
    };
    let mut senders: Vec<SenderView> =
        model.senders.iter().zip(sdps).map(|(sender, sdp)| sender_view(&model, sender, sdp)).collect();
    senders.sort_by_cached_key(|s| (s.label.to_lowercase(), s.id.clone()));
    let mut receivers: Vec<ReceiverView> = model.receivers.iter().map(|r| receiver_view(&model, r)).collect();
    receivers.sort_by_cached_key(|r| (r.label.to_lowercase(), r.id.clone()));
    Report {
        source: snapshot.source.clone(),
        api_version: snapshot.api_version.clone(),
        summary,
        senders,
        receivers,
        findings: findings.into_sorted(),
    }
}

/// Names a resource in a message about another one.
fn name(core: &Core<'_>) -> String {
    ResourceRef::of(core).describe()
}

/// Lists names for a message: `eth0, eth1`, or `none`. Past ten, says how many more.
fn list<'s>(items: impl IntoIterator<Item = &'s str>) -> String {
    let mut items = items.into_iter();
    let shown: Vec<&str> = items.by_ref().take(10).collect();
    match (shown.is_empty(), items.count()) {
        (true, _) => "none".into(),
        (false, 0) => shown.join(", "),
        (false, more) => format!("{} and {more} more", shown.join(", ")),
    }
}

fn resources(model: &Model<'_>, findings: &mut Findings) {
    for (kind, index, problems) in &model.problems {
        findings.add(&RESOURCE_INVALID, model.core(*kind, *index), problems.join("; "));
    }
    for core in model.cores() {
        if let Some(id) = core.id {
            if !is_uuid(id) {
                let message = if is_uuid(&id.to_ascii_lowercase()) {
                    format!("id {id} is in uppercase; IS-04 writes UUIDs in lowercase hex")
                } else {
                    format!("id {id} is not a UUID written like f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
                };
                findings.add(&RESOURCE_ID, core, message);
            }
            if let Some(first) = model.first(core.kind, id)
                && first.index != core.index
            {
                findings.add(&DUPLICATE_ID, core, format!("{} has the same id", name(first)));
            }
        }
        if let Some(version) = core.version
            && let Some(problem) = version_problem(version)
        {
            findings.add(&RESOURCE_VERSION, core, problem);
        }
    }
}

fn version_problem(version: &str) -> Option<String> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match version.split_once(':') {
        Some((seconds, nanos)) if digits(seconds) && digits(nanos) => match nanos.parse::<u64>() {
            Ok(n) if n < 1_000_000_000 => None,
            _ => Some(format!("version {version}: the nanoseconds part is not below 1000000000")),
        },
        _ => Some(format!("version {version} is not a TAI timestamp written <seconds>:<nanoseconds>")),
    }
}

fn references(model: &Model<'_>, findings: &mut Findings) {
    let mut interfaces = HashMap::new();
    let device = |core: &Core<'_>, id: Option<&str>, findings: &mut Findings| {
        if let Some(id) = id
            && model.device(id).is_none()
        {
            findings.add(&MISSING_PARENT, core, format!("its Device {id} is not registered"));
        }
    };
    for d in &model.devices {
        if let Some(id) = d.node_id
            && model.node(id).is_none()
        {
            findings.add(&MISSING_PARENT, &d.core, format!("its Node {id} is not registered"));
        }
    }
    for source in &model.sources {
        device(&source.core, source.device_id, findings);
        clock(model, source, findings);
    }
    for flow in &model.flows {
        let missing_source = flow.source_id.filter(|id| model.source(id).is_none());
        match (flow.device_id, missing_source) {
            (Some(_), Some(id)) => {
                findings.add(&UNKNOWN_REFERENCE, &flow.core, format!("its Source {id} is not registered"));
            }
            // An IS-04 v1.0 Flow has no Device; its Source is its parent.
            (None, Some(id)) => {
                findings.add(&MISSING_PARENT, &flow.core, format!("its Source {id} is not registered"));
            }
            _ => {}
        }
        device(&flow.core, flow.device_id, findings);
    }
    for sender in &model.senders {
        device(&sender.core, sender.device_id, findings);
        if let Some(id) = sender.flow_id
            && model.flow(id).is_none()
        {
            findings.add(&UNKNOWN_REFERENCE, &sender.core, format!("its Flow {id} is not registered"));
        }
        if let Some(id) = sender.subscription.as_ref().and_then(|s| s.peer)
            && model.receiver(id).is_none()
        {
            findings.add(
                &UNKNOWN_REFERENCE,
                &sender.core,
                format!("its subscription names Receiver {id}, which is not registered"),
            );
        }
        let bindings = sender.interface_bindings.as_deref();
        check_bindings(model, &mut interfaces, &sender.core, sender.device_id, bindings, findings);
    }
    for receiver in &model.receivers {
        device(&receiver.core, receiver.device_id, findings);
        if let Some(id) = receiver.sender_id()
            && model.sender(id).is_none()
        {
            findings.add(
                &UNKNOWN_REFERENCE,
                &receiver.core,
                format!("its subscription names Sender {id}, which is not registered"),
            );
        }
        let bindings = receiver.interface_bindings.as_deref();
        check_bindings(model, &mut interfaces, &receiver.core, receiver.device_id, bindings, findings);
    }
}

/// Checks that each interface a Sender or Receiver binds to is one its Node has.
/// `known` keeps each Node's interface names, by the Node's index, between calls.
fn check_bindings<'a>(
    model: &Model<'a>,
    known: &mut HashMap<usize, HashSet<&'a str>>,
    core: &Core<'_>,
    device: Option<&str>,
    bindings: Option<&[&str]>,
    f: &mut Findings,
) {
    let (Some(bindings), Some(node)) = (bindings, model.node_of(device)) else {
        return;
    };
    let Some(interfaces) = &node.interfaces else {
        return;
    };
    let known = known.entry(node.core.index).or_insert_with(|| interfaces.iter().copied().collect());
    let mut reported = HashSet::new();
    let mut names = None;
    for &name in bindings {
        if known.contains(name) || !reported.insert(name) {
            continue;
        }
        let message = if interfaces.is_empty() {
            format!("it binds to interface {name}, but its Node lists no interfaces")
        } else {
            let names = names.get_or_insert_with(|| list(interfaces.iter().copied()));
            format!("it binds to interface {name}, but its Node's interfaces are {names}")
        };
        f.add(&UNKNOWN_INTERFACE, core, message);
    }
}

fn clock(model: &Model<'_>, source: &Source<'_>, findings: &mut Findings) {
    let Some(name) = source.clock_name else {
        return;
    };
    let Some(node) = model.node_of(source.device_id) else {
        return;
    };
    let Some(clocks) = &node.clocks else {
        return;
    };
    if !clocks.iter().any(|c| c.name == name) {
        findings.add(
            &UNKNOWN_CLOCK,
            &source.core,
            format!("its clock_name is {name}, but its Node's clocks are {}", list(clocks.iter().map(|c| c.name))),
        );
    }
}

/// Checks the Nodes' PTP clocks; returns the grandmasters they follow and how many are unlocked.
fn ptp(model: &Model<'_>, findings: &mut Findings) -> (Vec<Grandmaster>, usize) {
    let mut followers: BTreeMap<String, Vec<(&Node<'_>, &Clock<'_>)>> = BTreeMap::new();
    let mut unlocked = 0;
    for node in &model.nodes {
        for clock in node.clocks.iter().flatten().filter(|c| c.is_ptp()) {
            match (clock.locked, clock.gmid) {
                (Some(false), _) => {
                    unlocked += 1;
                    findings.add(
                        &PTP_UNLOCKED,
                        &node.core,
                        format!(
                            "PTP clock {} is not locked, so its time has no defined relationship to the grandmaster",
                            clock.name
                        ),
                    );
                }
                (Some(true), Some(gmid)) => {
                    followers.entry(gmid.to_ascii_lowercase()).or_default().push((node, clock));
                }
                _ => {}
            }
        }
    }
    let mut grandmasters: Vec<Grandmaster> =
        followers.iter().map(|(id, clocks)| Grandmaster { id: id.clone(), clocks: clocks.len() }).collect();
    grandmasters.sort_by(|a, b| b.clocks.cmp(&a.clocks).then_with(|| a.id.cmp(&b.id)));
    // Grandmasters traceable to TAI keep the same time, so clocks that follow
    // different ones are still aligned.
    let traceable = |id: &str| followers[id].iter().all(|(_, clock)| clock.traceable == Some(true));
    if let [main, others @ ..] = grandmasters.as_slice() {
        let total: usize = grandmasters.iter().map(|g| g.clocks).sum();
        let main_traceable = traceable(&main.id);
        for other in others.iter().filter(|other| !main_traceable || !traceable(&other.id)) {
            for (node, clock) in &followers[&other.id] {
                findings.add(
                    &PTP_GRANDMASTERS,
                    &node.core,
                    format!(
                        "PTP clock {} follows grandmaster {}, but most locked clocks ({} of {total}) follow {}",
                        clock.name, other.id, main.clocks, main.id
                    ),
                );
            }
        }
    }
    (grandmasters, unlocked)
}

fn is_rtp(sender: &Sender<'_>) -> bool {
    sender.transport.is_some_and(|t| t == "urn:x-nmos:transport:rtp" || t.starts_with("urn:x-nmos:transport:rtp."))
}

/// Checks a Sender's `manifest_href` and what fetching it returned, and lints the SDP file.
fn transport_file(model: &Model<'_>, snapshot: &Snapshot, sender: &Sender<'_>, f: &mut Findings) -> Option<Sdp> {
    let core = &sender.core;
    if !is_rtp(sender) {
        return None;
    }
    let declared_null =
        snapshot.senders.get(core.index).and_then(|s| s.get("manifest_href")).is_some_and(Value::is_null);
    match sender.manifest_href {
        None if declared_null => {
            f.add(&MANIFEST_HREF, core, "manifest_href is null, so no controller can fetch its SDP file");
        }
        Some(href) if !is_http(href) => {
            f.add(&MANIFEST_HREF, core, format!("manifest_href {href} is not an HTTP(S) URL"));
        }
        _ => {}
    }
    let manifest: &Manifest = snapshot.manifests.get(core.id?)?;
    let active = sender.active();
    if let Some(error) = &manifest.error {
        f.add(&MANIFEST_UNREACHABLE, core, format!("fetching {} failed: {error}", manifest.url));
        return None;
    }
    match manifest.status {
        Some(404) if active == Some(false) => return None,
        Some(status) if !(200..300).contains(&status) => {
            let when = if active == Some(true) { " although the Sender is active" } else { "" };
            f.add(&MANIFEST_UNREACHABLE, core, format!("{} answered HTTP {status}{when}", manifest.url));
            return None;
        }
        _ => {}
    }
    let text = manifest.sdp.as_deref().filter(|t| !t.trim().is_empty());
    let Some(text) = text else {
        f.add(&MANIFEST_UNREACHABLE, core, format!("{} returned an empty file", manifest.url));
        return None;
    };
    let mut report = st2110_sdp::lint(text);
    let facts = SdpFacts::read(text, report.streams.first());
    f.sdp(core, std::mem::take(&mut report.diagnostics));
    let sdp = Sdp { report, facts };
    let streams = &sdp.report.streams;

    if let Some(bindings) = &sender.interface_bindings
        && !streams.is_empty()
        && bindings.len() != sdp.facts.legs
    {
        f.add(
            &INTERFACE_BINDINGS,
            core,
            format!(
                "it lists {} for the {} in its SDP file",
                count(bindings.len(), "interface binding"),
                count(sdp.facts.legs, "stream")
            ),
        );
    }
    transport_address(sender, streams, f);
    if let Some(stream) = streams.first() {
        let (flow, source) = model.flow_of(sender);
        if let Some(flow) = flow {
            flow_sdp(flow, source, stream, core, f);
        }
        sender_sdp(sender, stream, &sdp.facts, f);
        if let Some(source) = source {
            ptp_sdp(model, source, stream, core, f);
        }
    }
    Some(sdp)
}

pub(crate) fn is_http(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn count(n: usize, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{n} {noun}s") }
}

fn is_multicast(address: &str) -> Option<bool> {
    address.parse::<IpAddr>().ok().map(|ip| ip.is_multicast())
}

fn transport_address(sender: &Sender<'_>, streams: &[Stream], f: &mut Findings) {
    let want_multicast = match sender.transport {
        Some("urn:x-nmos:transport:rtp.mcast") => true,
        Some("urn:x-nmos:transport:rtp.ucast") => false,
        _ => return,
    };
    for stream in streams {
        let Some(address) = &stream.destination else { continue };
        if is_multicast(address) == Some(!want_multicast) {
            let (transport, kind) = if want_multicast { ("rtp.mcast", "unicast") } else { ("rtp.ucast", "multicast") };
            f.add(
                &TRANSPORT_ADDRESS,
                &sender.core,
                format!("it is an {transport} Sender, but its SDP file sends to {kind} address {address}"),
            );
            return;
        }
    }
}

/// A format parameter's value. Parameter names are not case-sensitive (RFC 2045 §5.1).
pub(crate) fn param<'s>(stream: &'s Stream, name: &str) -> Option<&'s str> {
    stream.parameters.iter().find(|p| p.name.eq_ignore_ascii_case(name)).and_then(|p| p.value.as_deref())
}

fn has_param(stream: &Stream, name: &str) -> bool {
    stream.parameters.iter().any(|p| p.name.eq_ignore_ascii_case(name))
}

/// Compares a Flow and its Source with the first stream of the Sender's SDP file.
fn flow_sdp(flow: &Flow<'_>, source: Option<&Source<'_>>, stream: &Stream, sender: &Core<'_>, f: &mut Findings) {
    let mut mismatch = |message: String| f.add(&FLOW_SDP, sender, message);
    if let (Some(media_type), Some(encoding)) = (flow.media_type, &stream.encoding) {
        let carried = format!("{}/{encoding}", stream.media);
        if !media_type.eq_ignore_ascii_case(&carried) {
            // Nothing else is comparable across two different formats.
            return mismatch(format!("its Flow is {media_type}, but its SDP file carries {carried}"));
        }
    }
    let format = flow.format.or_else(|| source?.format).map(short_urn);
    if let Some("video" | "data") = format
        && let Some(rate) = flow.grain_rate.or_else(|| source?.grain_rate)
        && let Some(text) = param(stream, "exactframerate")
        && let Ok((sdp_rate, _)) = parse_frame_rate(text)
        && sdp_rate != rate
    {
        mismatch(format!("its Flow's grain_rate is {rate}, but exactframerate is {sdp_rate}"));
    }
    match format {
        Some("video") => video_sdp(flow, stream, &mut mismatch),
        Some("audio") => audio_sdp(flow, source, stream, &mut mismatch),
        _ => {}
    }
}

fn video_sdp(flow: &Flow<'_>, stream: &Stream, mismatch: &mut impl FnMut(String)) {
    for (attribute, value, key) in
        [("frame_width", flow.frame_width, "width"), ("frame_height", flow.frame_height, "height")]
    {
        if let (Some(value), Some(text)) = (value, param(stream, key))
            && text.parse::<u64>().ok() != Some(value)
        {
            mismatch(format!("its Flow's {attribute} is {value}, but {key} is {text}"));
        }
    }
    let signalled = match (has_param(stream, "interlace"), has_param(stream, "segmented")) {
        (false, _) => "progressive",
        (true, false) => "interlaced",
        (true, true) => "PsF",
    };
    // IS-04 v1.1 added interlace_mode and transfer_characteristic, with their
    // defaults, along with media_type; a v1.0 Flow says nothing about either.
    let v1_1 = flow.media_type.is_some();
    let mode = flow.interlace_mode.or(v1_1.then_some("progressive"));
    let expected = match mode {
        Some("progressive") => Some("progressive"),
        Some("interlaced_tff" | "interlaced_bff") => Some("interlaced"),
        Some("interlaced_psf") => Some("PsF"),
        _ => None,
    };
    if let (Some(mode), Some(expected)) = (mode, expected)
        && expected != signalled
    {
        mismatch(format!("its Flow's interlace_mode is {mode}, but its SDP file signals {signalled} video"));
    }
    if let (Some(colorspace), Some(colorimetry)) = (flow.colorspace, param(stream, "colorimetry"))
        && colorspace != colorimetry
    {
        mismatch(format!("its Flow's colorspace is {colorspace}, but colorimetry is {colorimetry}"));
    }
    // Both default to SDR.
    let tcs = param(stream, "TCS").unwrap_or("SDR");
    if let Some(transfer) = flow.transfer_characteristic.or(v1_1.then_some("SDR"))
        && transfer != tcs
    {
        mismatch(format!("its Flow's transfer_characteristic is {transfer}, but TCS is {tcs}"));
    }
    if !flow.media_type.is_some_and(|m| m.eq_ignore_ascii_case("video/raw")) {
        return;
    }
    if let (Some(from_components), Some(sampling)) = (caps::sampling(&flow.components), param(stream, "sampling"))
        && from_components != sampling.strip_prefix("CL").unwrap_or(sampling)
    {
        mismatch(format!("its Flow's components are {from_components}, but sampling is {sampling}"));
    }
    if let (Some(depth), Some(text)) = (caps::component_depth(&flow.components), param(stream, "depth"))
        && text.trim_end_matches('f').parse::<u64>().ok() != Some(depth)
    {
        mismatch(format!("its Flow's components are {depth}-bit, but depth is {text}"));
    }
}

fn audio_sdp(flow: &Flow<'_>, source: Option<&Source<'_>>, stream: &Stream, mismatch: &mut impl FnMut(String)) {
    if let (Some(rate), Some(clock)) = (flow.sample_rate, stream.clock_rate)
        && Rational::new(u64::from(clock), 1) != Some(rate)
    {
        mismatch(format!("its Flow's sample_rate is {rate}, but the RTP clock runs at {clock} Hz"));
    }
    let encoding_depth =
        stream.encoding.as_deref().and_then(|e| e.strip_prefix('L')).and_then(|d| d.parse::<u64>().ok());
    if let (Some(depth), Some(encoded)) = (flow.bit_depth, encoding_depth)
        && depth != encoded
    {
        mismatch(format!("its Flow's bit_depth is {depth}, but the encoding is L{encoded}"));
    }
    if let (Some(channels), Some(sdp_channels)) = (source.and_then(|s| s.channels), stream.channels)
        && channels != usize::from(sdp_channels)
    {
        mismatch(format!("its Source has {}, but the SDP file carries {sdp_channels}", count(channels, "channel")));
    }
}

/// Compares the Sender attributes that have SDP counterparts.
fn sender_sdp(sender: &Sender<'_>, stream: &Stream, facts: &SdpFacts, f: &mut Findings) {
    let core = &sender.core;
    if let Some(sender_type) = sender.st2110_21_sender_type {
        match param(stream, "TP") {
            Some(tp) if tp == sender_type => {}
            Some(tp) => f.add(&SENDER_SDP, core, format!("its st2110_21_sender_type is {sender_type}, but TP is {tp}")),
            None => f.add(
                &SENDER_SDP,
                core,
                format!("its st2110_21_sender_type is {sender_type}, but its SDP file has no TP"),
            ),
        }
    }
    if let Some(packetmode) = param(stream, "packetmode") {
        // RFC 9134: transmode defaults to 1, sequential.
        let transmode = param(stream, "transmode").unwrap_or("1");
        let signalled = match (packetmode, transmode) {
            ("0", "1") => Some("codestream"),
            ("1", "1") => Some("slice_sequential"),
            ("1", "0") => Some("slice_out_of_order"),
            _ => None,
        };
        let mode = sender.packet_transmission_mode.unwrap_or("codestream");
        if let Some(signalled) = signalled
            && signalled != mode
        {
            f.add(
                &SENDER_SDP,
                core,
                format!(
                    "its packet_transmission_mode is {mode}, but packetmode={packetmode} and transmode={transmode} mean {signalled}"
                ),
            );
        }
    }
    if let (Some(bit_rate), Some(bandwidth)) = (sender.bit_rate, facts.bandwidth)
        && bit_rate.abs_diff(bandwidth) > 1
    {
        f.add(&SENDER_SDP, core, format!("its bit_rate is {bit_rate} kbit/s, but b=AS is {bandwidth}"));
    }
}

/// Compares the reference clock in the SDP file with the Source's clock on its Node.
fn ptp_sdp(model: &Model<'_>, source: &Source<'_>, stream: &Stream, sender: &Core<'_>, f: &mut Findings) {
    let Some(name) = source.clock_name else {
        return;
    };
    let Some(clock) = model.node_of(source.device_id).and_then(|n| n.clocks.as_ref()?.iter().find(|c| c.name == name))
    else {
        return;
    };
    match &stream.reference_clock {
        Some(RefClock::Ptp { grandmaster: Some(grandmaster), .. }) if clock.is_ptp() => {
            if clock.locked == Some(true)
                && let Some(gmid) = clock.gmid
                && ClockIdentity::parse(gmid).is_some_and(|id| id != *grandmaster)
            {
                f.add(
                    &PTP_SDP_GRANDMASTER,
                    sender,
                    format!(
                        "its SDP file names grandmaster {grandmaster}, but its Source's clock {name} follows {gmid}"
                    ),
                );
            }
        }
        Some(RefClock::Ptp { .. }) if clock.ref_type == "internal" => f.add(
            &PTP_SDP_GRANDMASTER,
            sender,
            format!("its SDP file names a PTP reference, but its Source's clock {name} is internal"),
        ),
        Some(RefClock::LocalMac { .. }) if clock.is_ptp() && clock.locked == Some(true) => f.add(
            &PTP_SDP_GRANDMASTER,
            sender,
            format!(
                "its SDP file says it free-runs (localmac), but its Source's clock {name} is locked to grandmaster {}",
                clock.gmid.unwrap_or("unknown")
            ),
        ),
        _ => {}
    }
}

fn subscriptions(model: &Model<'_>, sdps: &[Option<Sdp>], findings: &mut Findings) {
    for (sender, sdp) in model.senders.iter().zip(sdps) {
        let Some(subscription) = &sender.subscription else { continue };
        let Some(receiver) = subscription.peer else { continue };
        let multicast = sender.transport == Some("urn:x-nmos:transport:rtp.mcast")
            || sdp
                .as_ref()
                .and_then(|s| s.report.streams.first()?.destination.as_deref())
                .and_then(is_multicast)
                .unwrap_or(false);
        // Receivers fetch from these Senders, or subscribe through a broker.
        let pull = sender.transport.filter(|t| {
            matches!(*t, "urn:x-nmos:transport:dash" | "urn:x-nmos:transport:websocket" | "urn:x-nmos:transport:mqtt")
        });
        let message = if subscription.active == Some(false) {
            format!("subscription.receiver_id is {receiver} while the Sender is inactive; it must be null")
        } else if multicast {
            format!("subscription.receiver_id is {receiver}, but only a unicast Sender names its Receiver")
        } else if let Some(transport) = pull {
            format!(
                "subscription.receiver_id is {receiver}, but a {} Sender does not push to a Receiver, so it names none",
                short_urn(transport)
            )
        } else {
            continue;
        };
        findings.add(&SUBSCRIPTION_STATE, &sender.core, message);
    }
    for receiver in &model.receivers {
        let Some(subscription) = &receiver.subscription else { continue };
        if let (Some(sender), Some(false)) = (subscription.peer, subscription.active) {
            findings.add(
                &SUBSCRIPTION_STATE,
                &receiver.core,
                format!("subscription.sender_id is {sender} while the Receiver is inactive; it must be null"),
            );
        }
    }
}

/// Checks each active Receiver against the Sender it takes its stream from.
fn connections(model: &Model<'_>, sdps: &[Option<Sdp>], findings: &mut Findings) {
    for receiver in model.receivers.iter().filter(|r| r.active()) {
        let Some(index) = receiver.sender_id().and_then(|id| model.position(Kind::Sender, id)) else { continue };
        let sender = &model.senders[index];
        if sender.active() == Some(false) {
            findings.add(
                &INACTIVE_SENDER,
                &receiver.core,
                format!("it takes its stream from {}, which is not active, so nothing arrives", name(&sender.core)),
            );
        }
        let (Some(flow), source) = model.flow_of(sender) else { continue };
        let facts = StreamFacts { flow, source, sender, sdp: sdps[index].as_ref().map(|s| &s.facts) };
        if let Some(problem) = compatibility(receiver, &facts, &name(&sender.core)) {
            findings.add(&RECEIVER_CAPS, &receiver.core, problem);
        }
    }
}

/// Why a Receiver's capabilities reject the stream a Sender sends.
fn compatibility(receiver: &Receiver<'_>, stream: &StreamFacts<'_, '_>, sender: &str) -> Option<String> {
    let format = stream.flow.format.or_else(|| stream.source?.format);
    if let (Some(wanted), Some(format)) = (receiver.format, format)
        && wanted != format
    {
        return Some(format!("it is a {} Receiver, but {sender} sends {}", short_urn(wanted), short_urn(format)));
    }
    if let (Some(types), Some(media_type)) = (&receiver.media_types, stream.flow.media_type)
        && !types.is_empty()
        && !types.iter().any(|t| t.eq_ignore_ascii_case(media_type))
    {
        let types = list(types.iter().copied());
        return Some(format!("its caps.media_types ({types}) leave out {media_type}, which {sender} sends"));
    }
    let reasons = caps::evaluate(receiver.constraint_sets?, stream).err()?;
    Some(format!("none of its constraint sets accepts what {sender} sends: {}", reasons.join("; ")))
}

fn labels(model: &Model<'_>, device_id: Option<&str>) -> (Option<String>, Option<String>) {
    let device = device_id.and_then(|id| model.device(id));
    let node = model.node_of(device_id);
    (node.map(|n| n.core.label.to_string()), device.map(|d| d.core.label.to_string()))
}

fn sender_view(model: &Model<'_>, sender: &Sender<'_>, sdp: Option<Sdp>) -> SenderView {
    let (node, device) = labels(model, sender.device_id);
    let (flow, _) = model.flow_of(sender);
    let receivers = match sender.core.id {
        Some(id) => model
            .receivers
            .iter()
            .filter(|r| r.active() && r.sender_id() == Some(id))
            .filter_map(|r| r.core.id.map(str::to_string))
            .collect(),
        None => Vec::new(),
    };
    SenderView {
        id: sender.core.id.map(str::to_string),
        label: sender.core.label.to_string(),
        node,
        device,
        transport: sender.transport.map(str::to_string),
        active: sender.active(),
        flow_id: sender.flow_id.map(str::to_string),
        media_type: flow.and_then(|f| f.media_type).map(str::to_string),
        manifest_href: sender.manifest_href.map(str::to_string),
        streams: sdp.map(|s| s.report.streams).unwrap_or_default(),
        receivers,
    }
}

fn receiver_view(model: &Model<'_>, receiver: &Receiver<'_>) -> ReceiverView {
    let (node, device) = labels(model, receiver.device_id);
    let sender_id = receiver.sender_id();
    ReceiverView {
        id: receiver.core.id.map(str::to_string),
        label: receiver.core.label.to_string(),
        node,
        device,
        transport: receiver.transport.map(str::to_string),
        format: receiver.format.map(str::to_string),
        active: receiver.active(),
        sender_id: sender_id.map(str::to_string),
        sender_label: sender_id.and_then(|id| model.sender(id)).map(|s| s.core.label.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::version_problem;

    #[test]
    fn versions() {
        assert_eq!(version_problem("1439299836:10"), None);
        assert_eq!(version_problem("1439299836:999999999"), None);
        assert!(version_problem("1439299836:1000000000").is_some());
        assert!(version_problem("1439299836.10").is_some());
        assert!(version_problem(":10").is_some());
        assert!(version_problem("-1:10").is_some());
    }
}
