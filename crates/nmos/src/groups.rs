//! The tags that say what a resource belongs with and what it is: BCP-002-01 natural
//! groups (`urn:x-nmos:tag:grouphint/v1.0`), such as a camera's video and audio
//! Senders, and BCP-002-02 asset tags, which tell one box of a model from another.
//!
//! A controller takes a natural group as one: [`companions`] pairs the rest of a
//! Receiver's group with the rest of a Sender's, so that taking a camera's video to a
//! monitor takes its audio to the monitor's audio too.

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;
use serde_json::Value;

use crate::Snapshot;
use crate::check::{list, name};
use crate::model::{Core, Kind, Model};
use crate::report::Findings;
use crate::routing::{Endpoint, receiver_endpoint, route, sender_endpoint};
use crate::rules::{ASSET_TAGS, GROUP_HINT};

/// The tag a BCP-002-01 natural group is given under.
pub const GROUPHINT: &str = "urn:x-nmos:tag:grouphint/v1.0";

/// One value of a `grouphint` tag: `<group-name>:<role-in-group>[:<group-scope>]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupHint {
    /// The group's name, such as `Camera 1`.
    pub name: String,
    /// What the resource is in the group, such as `Audio 1`.
    pub role: String,
    /// Whether the group reaches across the Node rather than only the Device.
    pub node_scope: bool,
}

impl GroupHint {
    /// Reads one value of the tag: `None` for an empty one, which says nothing.
    pub fn parse(text: &str) -> Result<Option<GroupHint>, String> {
        if text.is_empty() {
            return Ok(None);
        }
        let parts: Vec<&str> = text.split(':').collect();
        let node_scope = match parts.as_slice() {
            [_, _] | [_, _, "device"] => false,
            [_, _, "node"] => true,
            [_, _, scope] => return Err(format!("\"{text}\" has scope \"{scope}\", where only device or node is")),
            [_] => return Err(format!("\"{text}\" has no role: it is written <group>:<role>")),
            _ => return Err(format!("\"{text}\" has more than three parts; `:` only separates them")),
        };
        if parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            return Err(format!("\"{text}\" leaves its group or its role empty"));
        }
        Ok(Some(GroupHint { name: parts[0].to_string(), role: parts[1].to_string(), node_scope }))
    }
}

/// The values of a resource's `grouphint` tag, as given.
fn hints(resource: &Value) -> Vec<&str> {
    resource
        .get("tags")
        .and_then(|t| t.get(GROUPHINT))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The natural group a Sender or Receiver is in: the first value of its `grouphint`
/// tag, which alone is the natural group, when it is well formed.
pub fn natural(resource: &Value) -> Option<GroupHint> {
    GroupHint::parse(hints(resource).first()?).ok().flatten()
}

/// A natural group, as a controller tells one from another: its name within the
/// Device or the Node it is scoped to, whose `id` this holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Group {
    /// The group's name.
    pub name: String,
    /// The `id` of the Device, or of the Node for a group with node scope.
    pub scope: String,
}

/// A Sender's or Receiver's natural group and its role there.
fn membership(model: &Model<'_>, resource: &Value, device_id: Option<&str>) -> Option<(Group, String)> {
    let hint = natural(resource)?;
    let device = device_id?;
    let scope = if hint.node_scope { model.device(device)?.node_id? } else { device };
    Some((Group { name: hint.name, scope: scope.to_string() }, hint.role))
}

/// Each Sender's or Receiver's natural group and role, keyed by its `id`.
pub fn memberships(snapshot: &Snapshot, kind: Kind) -> BTreeMap<String, (Group, String)> {
    let model = Model::read(snapshot);
    let found: Vec<(&Core<'_>, Option<&str>, &Value)> = match kind {
        Kind::Sender => model.senders.iter().map(|s| (&s.core, s.device_id, &snapshot.senders[s.core.index])).collect(),
        Kind::Receiver => {
            model.receivers.iter().map(|r| (&r.core, r.device_id, &snapshot.receivers[r.core.index])).collect()
        }
        _ => Vec::new(),
    };
    found
        .into_iter()
        .filter_map(|(core, device_id, raw)| Some((core.id?.to_string(), membership(&model, raw, device_id)?)))
        .collect()
}

/// Sorts names as a person reads them, so that `Audio 2` comes before `Audio 10`.
fn natural_key(text: &str) -> Vec<(u64, String)> {
    let mut key = Vec::new();
    let mut digits = String::new();
    let mut letters = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            if !letters.is_empty() {
                key.push((0, std::mem::take(&mut letters)));
            }
            digits.push(c);
        } else {
            if !digits.is_empty() {
                key.push((digits.parse().unwrap_or(u64::MAX), String::new()));
                digits.clear();
            }
            letters.extend(c.to_lowercase());
        }
    }
    if !digits.is_empty() {
        key.push((digits.parse().unwrap_or(u64::MAX), String::new()));
    }
    if !letters.is_empty() {
        key.push((0, letters));
    }
    key
}

/// The rest of a Receiver's natural group, and what each is to take so that the group
/// takes a Sender's group as one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Companions {
    /// The group the Receiver is in, when it is in one.
    pub group: Option<Group>,
    /// Each other Receiver in its group, with the Sender it is to take, or `None` to be
    /// disconnected.
    pub routes: Vec<(Endpoint, Option<Endpoint>)>,
    /// Why each Receiver of the group that was left as it is, was.
    pub left: Vec<String>,
}

/// Pairs the rest of `receiver_id`'s natural group with the rest of `sender_id`'s, as
/// BCP-002-01 has a controller treat a group as one: each Receiver takes the Sender of
/// its format with the same role, or else the next of that format in role order, when
/// it can take it. With no Sender, the rest of the group is disconnected too.
///
/// Empty when the Receiver is in no group.
pub fn companions(snapshot: &Snapshot, receiver_id: &str, sender_id: Option<&str>) -> Companions {
    let model = Model::read(snapshot);
    let Some(receiver) = model.receiver(receiver_id) else {
        return Companions::default();
    };
    let Some((group, _)) = membership(&model, &snapshot.receivers[receiver.core.index], receiver.device_id) else {
        return Companions::default();
    };
    let mut others: Vec<(String, Endpoint)> = model
        .receivers
        .iter()
        .filter(|r| r.core.id.is_some() && r.core.id != receiver.core.id)
        .filter_map(|r| {
            let (g, role) = membership(&model, &snapshot.receivers[r.core.index], r.device_id)?;
            (g == group).then(|| (role, receiver_endpoint(&model, r)))
        })
        .collect();
    others.sort_by_cached_key(|(role, e)| (natural_key(role), e.id.clone()));
    let mut companions = Companions { group: Some(group.clone()), ..Companions::default() };
    let Some(sender_id) = sender_id else {
        companions.routes = others.into_iter().map(|(_, e)| (e, None)).collect();
        return companions;
    };
    let Some(sender) = model.sender(sender_id) else {
        return companions;
    };
    let sender_name = name(&sender.core);
    let Some((sender_group, _)) = membership(&model, &snapshot.senders[sender.core.index], sender.device_id) else {
        if !others.is_empty() {
            let rest = list(others.iter().map(|(_, e)| e.label.as_str()));
            let are = if others.len() == 1 { "it is" } else { "they are" };
            companions.left.push(format!("{rest} left as {are}: {sender_name} is in no group"));
        }
        return companions;
    };
    let mut senders: Vec<(String, Endpoint)> = model
        .senders
        .iter()
        .filter(|s| s.core.id.is_some() && s.core.id != sender.core.id)
        .filter_map(|s| {
            let (g, role) = membership(&model, &snapshot.senders[s.core.index], s.device_id)?;
            (g == sender_group).then(|| (role, sender_endpoint(&model, s)))
        })
        .collect();
    senders.sort_by_cached_key(|(role, e)| (natural_key(role), e.id.clone()));
    // The same role first, then the rest of each format in role order.
    let mut taken: HashSet<String> = HashSet::new();
    let mut chosen: Vec<Option<usize>> = others
        .iter()
        .map(|(role, r)| {
            let i = senders.iter().position(|(s_role, s)| {
                s_role.eq_ignore_ascii_case(role) && s.format == r.format && !taken.contains(&s.id)
            })?;
            taken.insert(senders[i].1.id.clone());
            Some(i)
        })
        .collect();
    for (pick, (_, r)) in chosen.iter_mut().zip(&others) {
        if pick.is_none() {
            *pick = senders.iter().position(|(_, s)| s.format == r.format && !taken.contains(&s.id));
            if let Some(i) = pick {
                taken.insert(senders[*i].1.id.clone());
            }
        }
    }
    for (pick, (_, r)) in chosen.into_iter().zip(others) {
        let format = r.format.as_deref().map_or("matching", |f| f.rsplit(':').next().unwrap_or(f)).to_string();
        let Some(i) = pick else {
            companions.left.push(format!(
                "{} left as it is: group {} has no other {format} Sender for it",
                r.describe(),
                sender_group.name
            ));
            continue;
        };
        let s = &senders[i].1;
        match route(snapshot, &s.id, &r.id, None) {
            Ok(()) => companions.routes.push((r, Some(s.clone()))),
            Err(reason) => companions.left.push(format!(
                "{} left as it is: it cannot take {}: {reason}",
                r.describe(),
                s.describe()
            )),
        }
    }
    companions
}

/// Checks each `grouphint` tag is well formed and that no two Senders, or two
/// Receivers, share a role in one natural group (BCP-002-01).
pub(crate) fn check_groups(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    let mut roles: BTreeMap<(Kind, Group, String), Vec<&Core<'_>>> = BTreeMap::new();
    let members = model
        .senders
        .iter()
        .map(|s| (&s.core, s.device_id, &snapshot.senders[s.core.index]))
        .chain(model.receivers.iter().map(|r| (&r.core, r.device_id, &snapshot.receivers[r.core.index])));
    for (core, device_id, raw) in members {
        for text in hints(raw) {
            if let Err(problem) = GroupHint::parse(text) {
                findings.add(&GROUP_HINT, core, format!("grouphint {problem}"));
            }
        }
        if let Some((group, role)) = membership(model, raw, device_id) {
            roles.entry((core.kind, group, role.to_lowercase())).or_default().push(core);
        }
    }
    for ((_, group, _), cores) in roles {
        if let [first, rest @ ..] = cores.as_slice() {
            for core in rest {
                findings.add(
                    &GROUP_HINT,
                    core,
                    format!(
                        "it has the same role in group {} as {}; roles tell a group's members apart",
                        group.name,
                        name(first)
                    ),
                );
            }
        }
    }
}

/// The asset tags of BCP-002-02, and whether a Device must give one.
const ASSET: [(&str, &str, bool); 4] = [
    ("urn:x-nmos:tag:asset:manufacturer/v1.0", "Manufacturer", false),
    ("urn:x-nmos:tag:asset:product/v1.0", "Product Name", false),
    ("urn:x-nmos:tag:asset:instance-id/v1.0", "Instance Identifier", false),
    ("urn:x-nmos:tag:asset:function/v1.0", "Function", true),
];

/// Checks that each Node and Device that gives any BCP-002-02 asset tag gives all it
/// must, and that no two Nodes, or two Devices, give the same three.
pub(crate) fn check_assets(model: &Model<'_>, snapshot: &Snapshot, findings: &mut Findings) {
    let assets = model
        .nodes
        .iter()
        .map(|n| (&n.core, &snapshot.nodes[n.core.index]))
        .chain(model.devices.iter().map(|d| (&d.core, &snapshot.devices[d.core.index])));
    let mut seen: BTreeMap<(Kind, [String; 3]), &Core<'_>> = BTreeMap::new();
    for (core, raw) in assets {
        let Some(tags) = raw.get("tags").and_then(Value::as_object) else { continue };
        if !tags.keys().any(|k| k.starts_with("urn:x-nmos:tag:asset:")) {
            continue;
        }
        let device = core.kind == Kind::Device;
        let values = |urn: &str| -> Vec<&str> {
            tags.get(urn)
                .and_then(Value::as_array)
                .map(|v| v.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default()
        };
        let mut wrong = Vec::new();
        for (urn, what, devices_only) in ASSET {
            let n = values(urn).len();
            if devices_only {
                if device && n == 0 {
                    wrong.push(format!("no {what}"));
                }
            } else if n != 1 {
                wrong.push(if n == 0 { format!("no {what}") } else { format!("{n} values of {what}, where one is") });
            }
        }
        if !wrong.is_empty() {
            findings.add(&ASSET_TAGS, core, format!("it gives asset tags, but {}", wrong.join(", ")));
            continue;
        }
        let key = [0, 1, 2].map(|i| values(ASSET[i].0)[0].to_string());
        if let Some(first) = seen.get(&(core.kind, key.clone())) {
            findings.add(
                &ASSET_TAGS,
                core,
                format!(
                    "{} gives the same Manufacturer, Product Name and Instance Identifier ({})",
                    name(first),
                    key.join(", ")
                ),
            );
        } else {
            seen.insert((core.kind, key), core);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_group_hints() {
        let hint =
            |name: &str, role: &str, node_scope| Some(GroupHint { name: name.into(), role: role.into(), node_scope });
        assert_eq!(GroupHint::parse("Camera:Audio 1"), Ok(hint("Camera", "Audio 1", false)));
        assert_eq!(GroupHint::parse("tally:left:node"), Ok(hint("tally", "left", true)));
        assert_eq!(GroupHint::parse("MV PIP 1:Video:device"), Ok(hint("MV PIP 1", "Video", false)));
        assert_eq!(GroupHint::parse(""), Ok(None));
        assert!(GroupHint::parse("Camera").is_err());
        assert!(GroupHint::parse("Camera:Video:system").is_err());
        assert!(GroupHint::parse("a:b:node:x").is_err());
        assert!(GroupHint::parse(":Video").is_err());
    }

    #[test]
    fn sorts_roles_as_people_read_them() {
        let mut roles = vec!["audio 10", "Audio 2", "Primary", "audio 1"];
        roles.sort_by_key(|r| natural_key(r));
        assert_eq!(roles, ["audio 1", "Audio 2", "audio 10", "Primary"]);
    }
}
