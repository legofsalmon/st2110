//! The Node's IS-13 Annotation API, at `/x-nmos/annotation/v1.0/` on the Node's port,
//! which the Node lists in its `services`: a controller reads and changes the label,
//! description and tags of the Node and each of its resources, and resets them with
//! `null` to what the Node first gave ([`st2110_nmos::annotation`]). IS-13 is a work in
//! progress upstream; this follows its v1.0 draft.
//!
//! A change gives the resource a later version and registers it again, as any change to
//! a resource is, and is kept in a file (`--annotations`), by resource id, so that the
//! next run with the same ids starts with it (Behaviour: Persistence).

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use st2110_nmos::Kind;
use st2110_nmos::annotation::{self, Annotation};

use super::State;
use super::connection::{error, tai};

/// What the Node first gave its resources, which a reset restores, and where changes
/// are kept.
#[derive(Default)]
pub(super) struct Kept {
    /// Parallel to the Node's resources.
    initial: Vec<Annotation>,
    path: Option<PathBuf>,
}

impl Kept {
    /// Notes what the resources are first, then gives them what `path` kept for their
    /// ids, if anything; says what goes wrong reading it.
    pub(super) fn load(resources: &mut [(Kind, Value)], path: Option<PathBuf>) -> Self {
        let initial = resources.iter().map(|(_, r)| Annotation::of(r)).collect();
        if let Some(path) = &path {
            let kept = read(path);
            for (_, resource) in resources.iter_mut() {
                let id = resource["id"].as_str().unwrap_or_default();
                if let Some(annotation) = kept.get(id).and_then(Annotation::from_json) {
                    annotation.write_to(resource);
                }
            }
        }
        Self { initial, path }
    }

    /// Keeps the annotations that differ from what the Node first gave, replacing what
    /// was kept for these resources and leaving other Nodes' as they are.
    fn save(&self, resources: &[(Kind, Value)]) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut kept = read(path);
        for ((_, resource), initial) in resources.iter().zip(&self.initial) {
            let id = resource["id"].as_str().unwrap_or_default().to_string();
            let now = Annotation::of(resource);
            if now == *initial {
                kept.remove(&id);
            } else {
                kept.insert(id, now.to_json());
            }
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let temporary = path.with_extension("json.new");
        let text = serde_json::to_string_pretty(&Value::Object(kept)).unwrap_or_default();
        std::fs::write(&temporary, text + "\n")?;
        std::fs::rename(&temporary, path)
    }
}

/// What a file of annotations holds; nothing when it cannot be read.
fn read(path: &Path) -> Map<String, Value> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            serde_json::from_str::<Value>(&text).ok().and_then(|v| v.as_object().cloned()).unwrap_or_else(|| {
                eprintln!("NMOS: {} is not a file of annotations; it is left out", path.display());
                Map::new()
            })
        }
        Err(_) => Map::new(),
    }
}

/// A version later than `old`: `now`, or `old` and a nanosecond when that is not.
fn later(old: &str, now: &str) -> String {
    let parse = |v: &str| {
        let (s, n) = v.split_once(':')?;
        Some((s.parse::<u64>().ok()?, n.parse::<u64>().ok()?))
    };
    match (parse(old), parse(now)) {
        (Some(old), Some(new)) if new > old => now.to_string(),
        (Some((s, n)), _) if n >= 999_999_999 => format!("{}:0", s + 1),
        (Some((s, n)), _) => format!("{s}:{}", n + 1),
        _ => now.to_string(),
    }
}

/// Answers a request below `/x-nmos/annotation/v1.0`, `rest` being the path after it
/// (IS-13 v1.0 draft: APIs/AnnotationAPI.raml).
pub(super) fn route(state: &mut State, method: &str, rest: &str, body: &Value) -> (u16, Value) {
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    let read = |list: Value| if method == "GET" { (200, list) } else { error(405, "Method Not Allowed", "") };
    let kind = |name: &str| Kind::ALL.into_iter().find(|k| k.plural() == name && *k != Kind::Node);
    let index = match parts.as_slice() {
        [] => return read(json!(["node/"])),
        ["node"] => return read(json!(["self/", "sources/", "flows/", "devices/", "senders/", "receivers/"])),
        ["node", "self"] => state.resources.iter().position(|(k, _)| *k == Kind::Node),
        ["node", name] => {
            return match kind(name) {
                Some(kind) => read(Value::Array(
                    state
                        .resources
                        .iter()
                        .filter(|(k, _)| *k == kind)
                        .map(|(_, r)| json!(format!("{}/", r["id"].as_str().unwrap_or_default())))
                        .collect(),
                )),
                None => error(404, "Not Found", "no such resource type"),
            };
        }
        ["node", name, id] => {
            kind(name).and_then(|kind| state.resources.iter().position(|(k, r)| *k == kind && r["id"] == *id))
        }
        _ => None,
    };
    let Some(index) = index else {
        return error(404, "Not Found", "no such resource");
    };
    let shown = |state: &State| {
        let resource = &state.resources[index].1;
        Annotation::of(resource)
            .resource(resource["id"].as_str().unwrap_or_default(), resource["version"].as_str().unwrap_or_default())
    };
    match method {
        "GET" => (200, shown(state)),
        "PATCH" => {
            let current = Annotation::of(&state.resources[index].1);
            let next = match annotation::apply(&current, &state.annotations.initial[index], body) {
                Ok(next) => next,
                // The draft asks a controller to show `error` to the person who asked.
                Err(refused) => return error(refused.status(), refused.message(), ""),
            };
            let now = tai(super::Control::now(state));
            let (kind, resource) = &mut state.resources[index];
            let kind = *kind;
            next.write_to(resource);
            // Every successful PATCH gives a later version, changed or not (Behaviour:
            // Versioning).
            resource["version"] = json!(later(resource["version"].as_str().unwrap_or_default(), &now));
            state.changed.insert(index);
            state.counters.bump(kind);
            if let Some(responder) = &state.advertising {
                responder.set_txt(state.txt());
            }
            if let Err(e) = state.annotations.save(&state.resources) {
                let path = state.annotations.path.as_deref().unwrap_or(Path::new("")).display().to_string();
                eprintln!("NMOS: cannot keep the annotations in {path}: {e}");
            }
            (200, shown(state))
        }
        _ => error(405, "Method Not Allowed", "a resource's annotations are read with GET and changed with PATCH"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_only_go_forward() {
        assert_eq!(later("10:5", "11:0"), "11:0");
        assert_eq!(later("10:5", "10:5"), "10:6");
        assert_eq!(later("10:999999999", "9:0"), "11:0");
        assert_eq!(later("", "3:4"), "3:4");
    }

    #[test]
    fn keeps_what_differs_and_reads_it_back() {
        let dir = std::env::temp_dir().join(format!("st2110-annotations-{}", std::process::id()));
        let path = dir.join("node-annotations.json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Another Node's, which stays.
        std::fs::write(&path, r#"{"other": {"label": "x", "description": "", "tags": {}}}"#).unwrap();
        let first = json!({"id": "a", "version": "1:0", "label": "cam", "description": "", "tags": {}});
        let mut resources = vec![
            (Kind::Node, first.clone()),
            (Kind::Device, json!({"id": "b", "label": "d", "description": "", "tags": {}})),
        ];
        let kept = Kept::load(&mut resources, Some(path.clone()));
        resources[0].1["label"] = json!("Camera 1");
        kept.save(&resources).unwrap();
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["a"]["label"], "Camera 1");
        assert!(saved.get("b").is_none(), "unchanged, so not kept: {saved}");
        assert_eq!(saved["other"]["label"], "x");
        let mut again = vec![(Kind::Node, first)];
        let reloaded = Kept::load(&mut again, Some(path.clone()));
        assert_eq!(again[0].1["label"], "Camera 1");
        assert_eq!(reloaded.initial[0].label, "cam", "a reset still goes back to what the Node gave");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
