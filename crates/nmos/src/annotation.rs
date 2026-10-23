//! IS-13 Annotation: the label, description and tags of a Node's resources, which a
//! controller changes with a `PATCH` to the Node's Annotation API, and resets with
//! `null`.
//!
//! IS-13 is still a work in progress upstream: this follows the v1.0 draft on its
//! `v1.0-dev` branch (APIs/AnnotationAPI.raml and docs/Behaviour.md), which has no
//! release yet. A Node advertises the API in its `services` as [`SERVICE_TYPE`], its
//! `href` the API's base (Interoperability: IS-04, Discovery).
//!
//! [`apply`] is the Node's side of a `PATCH`: it checks the request against
//! `resource_core_patch.json`, keeps the tags this module treats as read only
//! ([`read_only_tag`]), and works out the new annotations, a reset restoring the value
//! the Node first gave.
//!
//! ```
//! use serde_json::json;
//! use st2110_nmos::annotation::{Annotation, apply};
//!
//! let first = Annotation::of(&json!({"label": "cam 1", "description": "", "tags": {}}));
//! let patched = apply(&first, &first, &json!({"label": "Camera 1", "tags": {"urn:x-nmos:tag:user:studio": ["HQ2"]}})).unwrap();
//! assert_eq!(patched.label, "Camera 1");
//! let reset = apply(&patched, &first, &json!({"label": null, "tags": null})).unwrap();
//! assert_eq!(reset, first);
//! ```

use serde_json::{Map, Value, json};

/// The service type a Node lists in its `services` for an Annotation API v1.0.
pub const SERVICE_TYPE: &str = "urn:x-nmos:service:annotation/v1.0";

/// Every version of the service type starts with this, then `/` and the version.
pub const SERVICE_PREFIX: &str = "urn:x-nmos:service:annotation";

/// The API version.
pub const VERSION: &str = "v1.0";

/// The namespace of tags every implementation lets a controller write
/// (Behaviour: Read-Write Tags).
pub const USER_TAG: &str = "urn:x-nmos:tag:user:";

/// The most bytes, in UTF-8, a label, a description, a tag's name or one of its values
/// may take here: well above the 64 the draft asks every implementation to take
/// (Behaviour: Additional Limitations).
pub const MOST_BYTES: usize = 1024;

/// The most tags a resource may have here.
pub const MOST_TAGS: usize = 64;

/// The most values one tag may have here.
pub const MOST_VALUES: usize = 16;

/// What can be annotated: the core properties of a resource that the Annotation API
/// shows besides its `id` and `version`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Annotation {
    /// `label`.
    pub label: String,
    /// `description`.
    pub description: String,
    /// `tags`: each a list of strings.
    pub tags: Map<String, Value>,
}

impl Annotation {
    /// Reads a resource's annotations; what is missing is empty.
    pub fn of(resource: &Value) -> Self {
        let text = |name: &str| resource.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
        Self {
            label: text("label"),
            description: text("description"),
            tags: resource.get("tags").and_then(Value::as_object).cloned().unwrap_or_default(),
        }
    }

    /// Writes the annotations into a resource, leaving the rest of it as it is.
    pub fn write_to(&self, resource: &mut Value) {
        if let Some(object) = resource.as_object_mut() {
            object.insert("label".into(), json!(self.label));
            object.insert("description".into(), json!(self.description));
            object.insert("tags".into(), Value::Object(self.tags.clone()));
        }
    }

    /// The annotations as JSON: `label`, `description` and `tags`.
    pub fn to_json(&self) -> Value {
        json!({"label": self.label, "description": self.description, "tags": self.tags})
    }

    /// Reads annotations kept as [`Annotation::to_json`] writes them.
    pub fn from_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let text = |name: &str| object.get(name)?.as_str().map(str::to_string);
        Some(Self {
            label: text("label")?,
            description: text("description")?,
            tags: object.get("tags")?.as_object()?.clone(),
        })
    }

    /// The resource as the Annotation API shows it: `id`, `version`, and these.
    pub fn resource(&self, id: &str, version: &str) -> Value {
        json!({"id": id, "version": version, "label": self.label, "description": self.description, "tags": self.tags})
    }
}

/// Whether a tag is one this module keeps read only: the BCP-002-01 natural grouping
/// hint and the BCP-002-02 asset tags, which the manufacturer assigns (Behaviour:
/// Read-Only Tags).
pub fn read_only_tag(name: &str) -> bool {
    name.starts_with("urn:x-nmos:tag:grouphint/") || name.starts_with("urn:x-nmos:tag:asset:")
}

/// Why a `PATCH` was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It breaks `resource_core_patch.json`: 400 (Bad Request).
    Invalid(String),
    /// It asks for what the API will not do, such as changing a read-only tag or giving
    /// a value larger than it keeps: 500 (Internal Server Error), as the draft has it.
    Rejected(String),
}

impl Refusal {
    /// The HTTP status to answer with.
    pub fn status(&self) -> u16 {
        match self {
            Self::Invalid(_) => 400,
            Self::Rejected(_) => 500,
        }
    }

    /// What went wrong, for the error response's `error`.
    pub fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Rejected(message) => message,
        }
    }
}

/// Checks a `PATCH` body against `resource_core_patch.json`: an object of `label`,
/// `description` and `tags` only, each a string or null, `tags` an object of arrays of
/// strings or nulls.
pub fn validate(patch: &Value) -> Result<(), String> {
    let Some(object) = patch.as_object() else {
        return Err("the request is not a JSON object".into());
    };
    for (key, value) in object {
        match key.as_str() {
            "label" | "description" if value.is_null() || value.is_string() => {}
            "label" | "description" => return Err(format!("{key} is a string, or null to reset it")),
            "tags" => {
                let Some(tags) = value.as_object() else {
                    if value.is_null() {
                        continue;
                    }
                    return Err("tags is an object, or null to reset them".into());
                };
                for (name, values) in tags {
                    let strings = values.as_array().is_some_and(|v| v.iter().all(Value::is_string));
                    if !values.is_null() && !strings {
                        return Err(format!("tag {name} is an array of strings, or null to reset it"));
                    }
                }
            }
            other => return Err(format!("{other} cannot be annotated: only label, description and tags")),
        }
    }
    Ok(())
}

fn too_long(what: &str, text: &str) -> Result<(), Refusal> {
    if text.len() > MOST_BYTES {
        return Err(Refusal::Rejected(format!(
            "{what} takes {} bytes; this Node keeps up to {MOST_BYTES}",
            text.len()
        )));
    }
    Ok(())
}

/// The annotations after a `PATCH`, from those the resource has now and those the Node
/// first gave it, which a `null` restores (Behaviour: Resetting Values). A read-only
/// tag may be named only with the value it has; `tags: null` leaves read-only tags as
/// they are.
pub fn apply(current: &Annotation, initial: &Annotation, patch: &Value) -> Result<Annotation, Refusal> {
    validate(patch).map_err(Refusal::Invalid)?;
    let mut next = current.clone();
    let text = |name: &str, first: &str| match patch.get(name) {
        None => None,
        Some(Value::Null) => Some(first.to_string()),
        Some(value) => value.as_str().map(str::to_string),
    };
    if let Some(label) = text("label", &initial.label) {
        too_long("the label", &label)?;
        next.label = label;
    }
    if let Some(description) = text("description", &initial.description) {
        too_long("the description", &description)?;
        next.description = description;
    }
    match patch.get("tags") {
        None => {}
        Some(Value::Null) => {
            let mut tags: Map<String, Value> = initial
                .tags
                .iter()
                .filter(|(name, _)| !read_only_tag(name))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            tags.extend(
                current.tags.iter().filter(|(name, _)| read_only_tag(name)).map(|(k, v)| (k.clone(), v.clone())),
            );
            next.tags = tags;
        }
        Some(Value::Object(tags)) => {
            for (name, values) in tags {
                let wanted = if values.is_null() { initial.tags.get(name).cloned() } else { Some(values.clone()) };
                if read_only_tag(name) {
                    if wanted.as_ref() != current.tags.get(name) {
                        return Err(Refusal::Rejected(format!("tag {name} is read only")));
                    }
                    continue;
                }
                match wanted {
                    Some(values) => {
                        too_long("a tag's name", name)?;
                        let list = values.as_array().map(Vec::as_slice).unwrap_or_default();
                        if list.len() > MOST_VALUES {
                            return Err(Refusal::Rejected(format!(
                                "tag {name} has {} values; this Node keeps up to {MOST_VALUES}",
                                list.len()
                            )));
                        }
                        for value in list {
                            too_long(&format!("a value of tag {name}"), value.as_str().unwrap_or_default())?;
                        }
                        next.tags.insert(name.clone(), values);
                    }
                    None => {
                        next.tags.remove(name);
                    }
                }
            }
            if next.tags.len() > MOST_TAGS {
                return Err(Refusal::Rejected(format!(
                    "that makes {} tags; this Node keeps up to {MOST_TAGS} for each resource",
                    next.tags.len()
                )));
            }
        }
        Some(_) => unreachable!("validated"),
    }
    Ok(next)
}

/// The URL of a Node's Annotation API v1.0, from its `services` (Interoperability:
/// IS-04, Discovery), ending in `/`.
pub fn service_href(node: &Value) -> Option<String> {
    node.get("services")?.as_array()?.iter().find_map(|service| {
        let kind = service.get("type")?.as_str()?;
        let version = kind.strip_prefix(SERVICE_PREFIX)?.strip_prefix('/')?;
        let href = service.get("href")?.as_str()?;
        (version == VERSION).then(|| format!("{}/", href.trim_end_matches('/')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first() -> Annotation {
        Annotation::of(&json!({
            "label": "host1", "description": "host1",
            "tags": {"urn:x-nmos:tag:grouphint/v1.0": ["cam 1:video"], "location": ["studio A"]},
        }))
    }

    #[test]
    fn sets_and_resets_as_the_draft_has_it() {
        let first = first();
        // Behaviour: Setting Values.
        let patched =
            apply(&first, &first, &json!({"label": "fave node", "description": "my favourite node"})).unwrap();
        assert_eq!((patched.label.as_str(), patched.description.as_str()), ("fave node", "my favourite node"));
        assert_eq!(patched.tags, first.tags, "tags untouched");
        let studio = apply(&patched, &first, &json!({"tags": {"studio": ["HQ2"]}})).unwrap();
        assert_eq!(studio.tags["studio"], json!(["HQ2"]));
        assert_eq!(studio.tags["location"], json!(["studio A"]));
        // Behaviour: Resetting Values: a tag with no initial value goes, one with an
        // initial value comes back.
        let moved = apply(&studio, &first, &json!({"tags": {"location": ["studio B"]}})).unwrap();
        let reset = apply(&moved, &first, &json!({"label": null, "tags": {"location": null, "studio": null}})).unwrap();
        assert_eq!(reset.label, "host1");
        assert_eq!(reset.description, "my favourite node");
        assert_eq!(reset.tags, first.tags);
        let all = apply(&studio, &first, &json!({"label": null, "description": null, "tags": null})).unwrap();
        assert_eq!(all, first);
    }

    #[test]
    fn keeps_read_only_tags_and_refuses_what_it_cannot_take() {
        let first = first();
        let group = "urn:x-nmos:tag:grouphint/v1.0";
        let refused = apply(&first, &first, &json!({"tags": {group: ["cam 2:video"]}})).unwrap_err();
        assert_eq!(refused.status(), 500, "{refused:?}");
        // Named with the value it has, or reset to it, it is no change.
        assert!(apply(&first, &first, &json!({"tags": {group: ["cam 1:video"]}})).is_ok());
        assert!(apply(&first, &first, &json!({"tags": {group: null}})).is_ok());
        let asset = "urn:x-nmos:tag:asset:manufacturer/v1.0";
        assert_eq!(apply(&first, &first, &json!({"tags": {asset: ["Acme"]}})).unwrap_err().status(), 500);
        // tags: null resets the rest, and leaves read-only tags alone.
        let mut current = first.clone();
        current.tags.insert(group.into(), json!(["cam 9:video"]));
        current.tags.insert("urn:x-nmos:tag:user:studio".into(), json!(["HQ2"]));
        let reset = apply(&current, &first, &json!({"tags": null})).unwrap();
        assert_eq!(reset.tags[group], json!(["cam 9:video"]));
        assert!(!reset.tags.contains_key("urn:x-nmos:tag:user:studio"));
        assert_eq!(reset.tags["location"], json!(["studio A"]));

        let long = "é".repeat(MOST_BYTES);
        assert_eq!(apply(&first, &first, &json!({"label": long})).unwrap_err().status(), 500);
        // The 64 bytes the draft asks for are taken.
        assert!(
            apply(
                &first,
                &first,
                &json!({"label": "x".repeat(64), "tags": {"urn:x-nmos:tag:user:a": ["y".repeat(64)]}})
            )
            .is_ok()
        );
        let many: Map<String, Value> =
            (0..=MOST_TAGS).map(|n| (format!("urn:x-nmos:tag:user:{n}"), json!(["x"]))).collect();
        assert_eq!(apply(&first, &first, &json!({"tags": many})).unwrap_err().status(), 500);
    }

    #[test]
    fn validates_against_the_patch_schema() {
        let first = first();
        for bad in [
            json!([]),
            json!({"id": "x"}),
            json!({"label": 1}),
            json!({"tags": []}),
            json!({"tags": {"a": "b"}}),
            json!({"tags": {"a": [1]}}),
        ] {
            assert_eq!(apply(&first, &first, &bad).unwrap_err().status(), 400, "{bad}");
        }
        assert_eq!(apply(&first, &first, &json!({})).unwrap(), first);
    }

    #[test]
    fn finds_the_service_and_keeps_annotations_as_json() {
        let node = json!({"services": [
            {"type": "urn:x-nmos:service:annotation/v2.0", "href": "http://a/x-nmos/annotation/v2.0/"},
            {"type": "urn:x-nmos:service:annotation/v1.0", "href": "http://a/x-nmos/annotation/v1.0"},
        ]});
        assert_eq!(service_href(&node).as_deref(), Some("http://a/x-nmos/annotation/v1.0/"));
        assert_eq!(service_href(&json!({"services": []})), None);
        let first = first();
        assert_eq!(Annotation::from_json(&first.to_json()), Some(first.clone()));
        let mut resource = json!({"id": "x", "label": "old"});
        first.write_to(&mut resource);
        assert_eq!(Annotation::of(&resource), first);
        assert_eq!(first.resource("x", "1:0")["version"], "1:0");
    }
}
