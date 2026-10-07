//! What a controller reads from a registry before it makes a connection: the Sender or
//! Receiver a name refers to, the IS-05 Connection API its Device advertises, and which
//! Senders each Receiver can take.
//!
//! Everything here only reads a [`Snapshot`]. The `st2110-connect` crate makes the
//! connections.

use std::net::IpAddr;

use serde::Serialize;
use st2110_sdp::Essence;

use crate::Snapshot;
use crate::caps::{SdpFacts, StreamFacts};
use crate::check::{compatibility, is_http, list, name};
use crate::model::{Core, Device, Kind, Model, Receiver, Sender, short_urn};
use crate::report::ResourceRef;

/// The control type an IS-05 Connection API is advertised under, before its version.
const SR_CTRL: &str = "urn:x-nmos:control:sr-ctrl/";

/// An IS-05 Connection API that a Device advertises in its `controls`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionApi {
    /// The API version, such as `v1.1`.
    pub version: String,
    /// The versioned base URL, such as `http://192.168.10.21/x-nmos/connection/v1.1/`.
    pub href: String,
}

/// A Sender or Receiver, as a controller finds it in the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    /// Sender or Receiver.
    pub kind: Kind,
    /// Its `id`.
    pub id: String,
    /// Its `label`, which may be empty.
    pub label: String,
    /// Its IS-04 `version`, which the Node advances whenever a connection changes.
    pub version: Option<String>,
    /// The label of its Node.
    pub node: Option<String>,
    /// The label of its Device.
    pub device: Option<String>,
    /// The transport URN, such as `urn:x-nmos:transport:rtp.mcast`.
    pub transport: Option<String>,
    /// The format URN: a Receiver's own, or that of the Flow a Sender sends.
    pub format: Option<String>,
    /// Where a Sender publishes its SDP file.
    pub manifest_href: Option<String>,
    /// Whether it is sending or receiving; `None` for a Sender from before IS-04 v1.2.
    pub active: Option<bool>,
    /// The Sender a Receiver takes its stream from, or the Receiver a unicast Sender
    /// sends to.
    pub subscription: Option<String>,
    /// The Connection API that controls it: its Device's newest IS-05 v1 control.
    pub connection_api: Option<ConnectionApi>,
}

impl Endpoint {
    /// A short name for messages, such as `receiver "MON 1 video" (7ecf0001)`.
    pub fn describe(&self) -> String {
        ResourceRef { kind: self.kind, id: Some(self.id.clone()), label: self.label.clone(), index: 0 }.describe()
    }
}

/// The Connection APIs a Device advertises, newest version first. Only IS-05 v1
/// versions with an HTTP(S) URL are listed: every v1 minor version takes the requests
/// v1.0 defines.
fn connection_apis(device: &Device<'_>) -> Vec<ConnectionApi> {
    let mut apis: Vec<((u32, u32), ConnectionApi)> = device
        .controls
        .iter()
        .flatten()
        .filter_map(|control| {
            let version = control.kind.strip_prefix(SR_CTRL)?;
            let (major, minor) = version.strip_prefix('v')?.split_once('.')?;
            let number = (major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?);
            if number.0 != 1 || !is_http(control.href) {
                return None;
            }
            // The href names the versioned base; add the version where it stops short.
            let trimmed = control.href.trim().trim_end_matches('/');
            let href = if trimmed.ends_with("/x-nmos/connection") {
                format!("{trimmed}/{version}/")
            } else {
                format!("{trimmed}/")
            };
            Some((number, ConnectionApi { version: version.to_string(), href }))
        })
        .collect();
    apis.sort_by_key(|a| std::cmp::Reverse(a.0));
    apis.into_iter().map(|(_, api)| api).collect()
}

/// Where each RTP Sender's Connection API serves its SDP file, `/transportfile`, keyed
/// by Sender `id`, for the Senders whose `manifest_href` names another URL.
#[cfg(feature = "client")]
pub(crate) fn transport_file_urls(snapshot: &Snapshot) -> Vec<(String, String)> {
    use crate::check::is_rtp;

    let model = Model::read(snapshot);
    let same = |a: &str, b: &str| a.trim().trim_end_matches('/').eq_ignore_ascii_case(b.trim().trim_end_matches('/'));
    model
        .senders
        .iter()
        .filter(|sender| is_rtp(sender))
        .filter_map(|sender| {
            let id = sender.core.id?;
            let api = connection_apis(model.device(sender.device_id?)?).into_iter().next()?;
            let url = format!("{}single/senders/{id}/transportfile", api.href);
            (!sender.manifest_href.is_some_and(|href| same(href, &url))).then(|| (id.to_string(), url))
        })
        .collect()
}

fn endpoint(model: &Model<'_>, core: &Core<'_>, device_id: Option<&str>) -> Endpoint {
    let device = device_id.and_then(|id| model.device(id));
    let node = model.node_of(device_id);
    Endpoint {
        kind: core.kind,
        id: core.id.unwrap_or_default().to_string(),
        label: core.label.to_string(),
        version: core.version.map(str::to_string),
        node: node.map(|n| n.core.label.to_string()),
        device: device.map(|d| d.core.label.to_string()),
        transport: None,
        format: None,
        manifest_href: None,
        active: None,
        subscription: None,
        connection_api: device.and_then(|d| connection_apis(d).into_iter().next()),
    }
}

fn sender_endpoint(model: &Model<'_>, sender: &Sender<'_>) -> Endpoint {
    let (flow, source) = model.flow_of(sender);
    Endpoint {
        transport: sender.transport.map(str::to_string),
        format: flow.and_then(|f| f.format).or_else(|| source?.format).map(str::to_string),
        manifest_href: sender.manifest_href.map(str::to_string),
        active: sender.active(),
        subscription: sender.subscription.as_ref().and_then(|s| s.peer).map(str::to_string),
        ..endpoint(model, &sender.core, sender.device_id)
    }
}

fn receiver_endpoint(model: &Model<'_>, receiver: &Receiver<'_>) -> Endpoint {
    Endpoint {
        transport: receiver.transport.map(str::to_string),
        format: receiver.format.map(str::to_string),
        active: Some(receiver.active()),
        subscription: receiver.sender_id().map(str::to_string),
        ..endpoint(model, &receiver.core, receiver.device_id)
    }
}

/// Every Sender with an `id`, as a controller lists them: in label order.
pub fn senders(snapshot: &Snapshot) -> Vec<Endpoint> {
    let model = Model::read(snapshot);
    let mut senders: Vec<Endpoint> =
        model.senders.iter().filter(|s| s.core.id.is_some()).map(|s| sender_endpoint(&model, s)).collect();
    senders.sort_by_cached_key(|e| (e.label.to_lowercase(), e.id.clone()));
    senders
}

/// Finds the Sender or Receiver that `selector` names: by its `id`, its `label`
/// (ignoring case), or the start of its `id`, in that order.
///
/// Fails when nothing matches, when a label or the start of an id matches more than
/// one, or when `kind` is neither [`Kind::Sender`] nor [`Kind::Receiver`].
pub fn find(snapshot: &Snapshot, kind: Kind, selector: &str) -> Result<Endpoint, String> {
    let model = Model::read(snapshot);
    let cores: Vec<&Core<'_>> = match kind {
        Kind::Sender => model.senders.iter().map(|s| &s.core).collect(),
        Kind::Receiver => model.receivers.iter().map(|r| &r.core).collect(),
        _ => return Err(format!("only Senders and Receivers are connected, not a {}", kind.as_str())),
    };
    let wanted = selector.trim();
    if wanted.is_empty() {
        return Err(format!("no {} was named", kind.as_str()));
    }
    let lower = wanted.to_ascii_lowercase();
    let with_id = || cores.iter().copied().filter(|c| c.id.is_some());
    let by_id: Vec<&Core<'_>> = with_id().filter(|c| c.id.is_some_and(|id| id.eq_ignore_ascii_case(wanted))).collect();
    let by_label: Vec<&Core<'_>> = with_id().filter(|c| c.label.trim().eq_ignore_ascii_case(wanted)).collect();
    let by_prefix: Vec<&Core<'_>> =
        with_id().filter(|c| c.id.is_some_and(|id| id.to_ascii_lowercase().starts_with(&lower))).collect();
    let (mut matches, how) = [(by_id, "have the id"), (by_label, "are labelled"), (by_prefix, "have an id starting")]
        .into_iter()
        .find(|(matches, _)| !matches.is_empty())
        .ok_or_else(|| format!("no {} has the id or label {wanted}", kind.as_str()))?;
    let [core] = matches.as_slice() else {
        matches.sort_by_cached_key(|c| (c.label.to_lowercase(), c.id));
        let names: Vec<String> = matches.iter().map(|c| name(c)).collect();
        return Err(format!(
            "{} {}s {how} {wanted}: {}; name one by its id",
            matches.len(),
            kind.as_str(),
            list(names.iter().map(String::as_str))
        ));
    };
    Ok(match kind {
        Kind::Sender => sender_endpoint(&model, &model.senders[core.index]),
        _ => receiver_endpoint(&model, &model.receivers[core.index]),
    })
}

/// Whether a Receiver of `receiver` can take a stream sent over `sender`: the two
/// transports share a base, and are not one multicast only and the other unicast only.
fn transports_meet(receiver: &str, sender: &str) -> bool {
    let base = |t: &'_ str| t.split_once('.').map_or(t, |(base, _)| base).to_string();
    base(receiver) == base(sender) && (receiver == sender || !receiver.contains('.') || !sender.contains('.'))
}

/// What each Sender's SDP file tells the capability checks.
fn sdp_facts(model: &Model<'_>, snapshot: &Snapshot) -> Vec<Option<SdpFacts>> {
    model
        .senders
        .iter()
        .map(|sender| {
            let text = snapshot.manifests.get(sender.core.id?)?.sdp.as_deref()?;
            let report = st2110_sdp::lint(text);
            Some(SdpFacts::read(text, report.streams.first()))
        })
        .collect()
}

/// Why `receiver` cannot take what `sender` sends, or `None` when nothing stands in the way.
fn fits(model: &Model<'_>, sender: &Sender<'_>, sdp: Option<&SdpFacts>, receiver: &Receiver<'_>) -> Option<String> {
    let sender_name = name(&sender.core);
    if let (Some(r), Some(s)) = (receiver.transport, sender.transport)
        && !transports_meet(r, s)
    {
        return Some(format!("it receives {}, but {sender_name} sends {}", short_urn(r), short_urn(s)));
    }
    let (Some(flow), source) = model.flow_of(sender) else {
        return None;
    };
    compatibility(receiver, &StreamFacts { flow, source, sender, sdp }, &sender_name)
}

/// Why a Receiver cannot take a Sender's stream: their transports differ, or the
/// Receiver's format, media types or BCP-004-01 capabilities reject it, judged on the
/// Sender's Flow and on its SDP file: `sdp`, or else the one the snapshot holds. `Ok`
/// when nothing stands in the way, or nothing is known that would.
pub fn route(snapshot: &Snapshot, sender_id: &str, receiver_id: &str, sdp: Option<&str>) -> Result<(), String> {
    let model = Model::read(snapshot);
    let sender = model.sender(sender_id).ok_or_else(|| format!("sender {sender_id} is not registered"))?;
    let receiver = model.receiver(receiver_id).ok_or_else(|| format!("receiver {receiver_id} is not registered"))?;
    let sdp = sdp.or_else(|| snapshot.manifests.get(sender_id)?.sdp.as_deref()).map(|text| {
        let report = st2110_sdp::lint(text);
        SdpFacts::read(text, report.streams.first())
    });
    fits(&model, sender, sdp.as_ref(), receiver).map_or(Ok(()), Err)
}

/// Why a Receiver cannot take the stream an SDP file from outside NMOS describes: it
/// receives another transport, or its format or `caps.media_types` leave the stream
/// out, judged on the file's first media section. With no Flow to judge them on, its
/// BCP-004-01 constraint sets are not checked. `Ok` when nothing stands in the way.
pub fn route_sdp(snapshot: &Snapshot, sdp: &str, receiver_id: &str) -> Result<(), String> {
    let model = Model::read(snapshot);
    let receiver = model.receiver(receiver_id).ok_or_else(|| format!("receiver {receiver_id} is not registered"))?;
    let report = st2110_sdp::lint(sdp);
    let Some(stream) = report.streams.first() else {
        return Ok(());
    };
    let multicast = stream.destination.as_deref().and_then(|d| d.parse::<IpAddr>().ok()).map(|ip| ip.is_multicast());
    if let (Some(r), Some(multicast)) = (receiver.transport, multicast) {
        let sent = if multicast { "urn:x-nmos:transport:rtp.mcast" } else { "urn:x-nmos:transport:rtp.ucast" };
        if !transports_meet(r, sent) {
            return Err(format!("it receives {}, but the SDP file describes {}", short_urn(r), short_urn(sent)));
        }
    }
    let format = match stream.essence {
        Essence::Video | Essence::CompressedVideo => Some("urn:x-nmos:format:video"),
        Essence::Audio | Essence::Aes3 => Some("urn:x-nmos:format:audio"),
        Essence::Ancillary | Essence::FastMetadata | Essence::TimedText => Some("urn:x-nmos:format:data"),
        Essence::Sdi => Some("urn:x-nmos:format:mux"),
        _ => None,
    };
    if let (Some(wanted), Some(format)) = (receiver.format, format)
        && wanted != format
    {
        return Err(format!(
            "it is a {} Receiver, but the SDP file describes {}",
            short_urn(wanted),
            short_urn(format)
        ));
    }
    if let (Some(types), Some(encoding)) = (&receiver.media_types, &stream.encoding)
        && !types.is_empty()
    {
        let carried = format!("{}/{encoding}", stream.media);
        if !types.iter().any(|t| t.eq_ignore_ascii_case(&carried)) {
            let types = list(types.iter().copied());
            return Err(format!("its caps.media_types ({types}) leave out {carried}, which the SDP file describes"));
        }
    }
    Ok(())
}

/// Which Senders each Receiver can take: the crosspoint matrix a router panel shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Matrix {
    /// Every Sender with an `id`, in label order.
    pub senders: Vec<ResourceRef>,
    /// Every Receiver with an `id`, in label order.
    pub receivers: Vec<MatrixRow>,
}

/// One Receiver's row of the [`Matrix`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MatrixRow {
    /// The Receiver.
    pub receiver: ResourceRef,
    /// Positions in [`Matrix::senders`] of the Senders whose streams it can take, as
    /// [`route`] judges them.
    pub fits: Vec<usize>,
    /// The position of the Sender it is taking a stream from now, when that is registered.
    pub current: Option<usize>,
}

/// The crosspoint matrix: for every Receiver, the Senders it can take, as [`route`]
/// judges each pair.
pub fn matrix(snapshot: &Snapshot) -> Matrix {
    let model = Model::read(snapshot);
    let facts = sdp_facts(&model, snapshot);
    let by_label =
        |a: &Core<'_>, b: &Core<'_>| a.label.to_lowercase().cmp(&b.label.to_lowercase()).then(a.id.cmp(&b.id));
    let mut senders: Vec<usize> = (0..model.senders.len()).filter(|&i| model.senders[i].core.id.is_some()).collect();
    senders.sort_by(|&a, &b| by_label(&model.senders[a].core, &model.senders[b].core));
    let mut receivers: Vec<&Receiver<'_>> = model.receivers.iter().filter(|r| r.core.id.is_some()).collect();
    receivers.sort_by(|a, b| by_label(&a.core, &b.core));
    let rows = receivers
        .into_iter()
        .map(|receiver| {
            let fits = senders
                .iter()
                .enumerate()
                .filter(|&(_, &i)| fits(&model, &model.senders[i], facts[i].as_ref(), receiver).is_none())
                .map(|(position, _)| position)
                .collect();
            let current = receiver
                .sender_id()
                .filter(|_| receiver.active())
                .and_then(|id| senders.iter().position(|&i| model.senders[i].core.id == Some(id)));
            MatrixRow { receiver: ResourceRef::of(&receiver.core), fits, current }
        })
        .collect();
    Matrix { senders: senders.iter().map(|&i| ResourceRef::of(&model.senders[i].core)).collect(), receivers: rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transports_must_share_a_base() {
        let meet = |r: &str, s: &str| {
            transports_meet(&format!("urn:x-nmos:transport:{r}"), &format!("urn:x-nmos:transport:{s}"))
        };
        assert!(meet("rtp", "rtp.mcast") && meet("rtp.mcast", "rtp") && meet("rtp.ucast", "rtp.ucast"));
        assert!(!meet("rtp.ucast", "rtp.mcast"));
        assert!(!meet("websocket", "rtp"));
    }
}
