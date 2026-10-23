//! The Node's IS-14 v1.0 Configuration API, at `/x-nmos/configuration/v1.0/` on the
//! Node's port, which its Device lists in `controls` as
//! `urn:x-nmos:control:configuration/v1.0`: the IS-12 Device model ([`super::ncp`]) over
//! HTTP, by role path (`root`, `root.DeviceManager`, `root.ClassManager`,
//! `root.receiver-monitor` or `root.sender-monitor`).
//!
//! Each object's properties are read and set by id (`1p6` is `userLabel`), its methods
//! called with `PATCH`, and its class and the datatype of each property described. Its
//! `bulkProperties` give a backup (`GET`, as an `NcBulkPropertiesHolder`), check a
//! restore of one (`PATCH`) and make it (`PUT`). Nothing in the model is rebuildable, so a
//! restore, `Modify` or `Rebuild`, sets the writable properties whose values differ and
//! leaves the rest with a notice: a `Warning` for each read-only property and each the
//! object does not have, an `Error` for a value the object refuses, which fails that
//! object and leaves it as it was. An object the backup names and the model has not is
//! answered `NotFound`.

use serde_json::{Value, json};
use st2110_nmos::ncp::{self, ElementId, method};

use super::ncp::{Model, failed, ok};
use crate::http::{Request, Response};

/// The version of the Configuration API the Node serves.
pub(crate) const VERSION: &str = "v1.0";

/// The control type the Device lists for it.
pub(crate) const CONTROL_TYPE: &str = "urn:x-nmos:control:configuration/v1.0";

/// `NcRestoreValidationStatus` and `NcPropertyRestoreNoticeType` values.
const OK: u64 = 200;
const FAILED: u64 = 400;
const NOT_FOUND: u64 = 404;
const WARNING: u64 = 300;
const ERROR: u64 = 400;

/// The answer to a request: an `NcMethodResult`, with the HTTP status its own gives.
fn result(value: Value) -> Response {
    let status = match value["status"].as_u64().unwrap_or(500) {
        0..300 => 200,
        404 => 404,
        400..500 => 400,
        _ => 500,
    };
    Response::json(status, &value)
}

fn list(items: impl IntoIterator<Item = String>) -> Response {
    Response::json(200, &json!(items.into_iter().map(|i| format!("{i}/")).collect::<Vec<_>>()))
}

/// A property or method id as a URL gives it, `1p6` or `2m1`.
fn element(text: &str, kind: char) -> Option<ElementId> {
    let (level, index) = text.split_once(kind)?;
    Some(ElementId::new(level.parse().ok()?, index.parse().ok()?))
}

/// Answers a request below `/x-nmos/configuration/v1.0`, `rest` being the path after it.
pub(crate) fn route(model: &mut Model, request: &Request, rest: &str, body: &Value) -> Response {
    let method = request.method.as_str();
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    let refused = |allowed: &str| result(failed(405, format!("{rest}: use {allowed}")));
    let paths = model.role_paths();
    let [_, role_path, below @ ..] = parts.as_slice() else {
        return match (parts.as_slice(), method) {
            ([], "GET") => list(["rolePaths".to_string()]),
            (["rolePaths"], "GET") => list(paths.iter().map(|(path, _)| path.join("."))),
            ([] | ["rolePaths"], _) => refused("GET"),
            _ => result(failed(404, format!("{rest} is not a path of the Configuration API"))),
        };
    };
    if parts[0] != "rolePaths" {
        return result(failed(404, format!("{rest} is not a path of the Configuration API")));
    }
    let Some((path, oid)) = paths.iter().find(|(path, _)| path.join(".") == *role_path).cloned() else {
        return result(failed(404, format!("this Device has no object at role path {role_path}")));
    };
    let class = model.class_of(oid).expect("every role path's object has a class");
    let property = |id: &str| {
        element(id, 'p')
            .and_then(|id| class.property(id))
            .ok_or_else(|| result(failed(404, format!("{} has no property {id}", class.name))))
    };
    match (below, method) {
        ([], "GET") => list(["bulkProperties", "descriptor", "methods", "properties"].map(String::from)),
        (["descriptor"], "GET") => result(ok(class.descriptor(true))),
        (["properties"], "GET") => {
            let mut ids: Vec<ElementId> = class.properties().iter().map(|p| p.id).collect();
            ids.sort_by_key(|id| (id.level, id.index));
            list(ids.into_iter().map(|id| format!("{}p{}", id.level, id.index)))
        }
        (["properties", id], "GET") => match property(id) {
            Ok(_) => list(["descriptor", "value"].map(String::from)),
            Err(response) => response,
        },
        (["properties", id, "descriptor"], "GET") => match property(id) {
            Ok(p) => match p.type_name.and_then(|name| ncp::datatype(name, true)) {
                Some(descriptor) => result(ok(descriptor)),
                None => result(failed(404, format!("{} has no datatype this Device describes", p.name))),
            },
            Err(response) => response,
        },
        (["properties", id, "value"], "GET" | "PUT") => match property(id) {
            Ok(p) if method == "GET" => result(model.command(oid, method::GET, &json!({"id": p.id.json()}), now())),
            Ok(p) => match body.get("value") {
                Some(value) => {
                    result(model.command(oid, method::SET, &json!({"id": p.id.json(), "value": value}), now()))
                }
                None => result(failed(400, "the body is {\"value\": …}")),
            },
            Err(response) => response,
        },
        (["methods"], "GET") => {
            let mut ids = class.methods();
            ids.sort_by_key(|id| (id.level, id.index));
            list(ids.into_iter().map(|id| format!("{}m{}", id.level, id.index)))
        }
        (["methods", id], "PATCH") => match element(id, 'm').filter(|m| class.has_method(*m)) {
            Some(m) => match body.get("arguments").filter(|a| a.is_object()) {
                Some(arguments) => result(model.command(oid, m, arguments, now())),
                None => result(failed(400, "the body is {\"arguments\": {…}}")),
            },
            None => result(failed(404, format!("{} has no method {id}", class.name))),
        },
        (["bulkProperties"], "GET") => {
            let flag = |name: &str| request.param(name).is_none_or(|v| v != "false");
            result(ok(backup(model, &path, flag("recurse"), flag("includeDescriptors"))))
        }
        (["bulkProperties"], "PUT" | "PATCH") => match restore(model, &path, body, method == "PUT") {
            Ok(validations) => result(ok(validations)),
            Err(why) => result(failed(400, why)),
        },
        (["methods", _], _) => refused("PATCH"),
        (["properties", _, "value"], _) => refused("GET or PUT"),
        (["bulkProperties"], _) => refused("GET, PUT or PATCH"),
        ([] | ["descriptor" | "properties" | "methods"] | ["properties", _] | ["properties", _, "descriptor"], _) => {
            refused("GET")
        }
        _ => result(failed(404, format!("{rest} is not a path of the Configuration API"))),
    }
}

fn now() -> std::time::Instant {
    std::time::Instant::now()
}

/// Whether `path` is `target` or, with `recurse`, below it.
fn within(path: &[String], target: &[String], recurse: bool) -> bool {
    path == target || (recurse && path.len() > target.len() && path.starts_with(target))
}

/// The `NcBulkPropertiesHolder` of the objects at and, with `recurse`, below `target`:
/// a backup, full from `root` (IS-14 v1.0 Backup & restore: Performing a backup).
/// Without descriptors, the ClassManager is left out.
fn backup(model: &Model, target: &[String], recurse: bool, descriptors: bool) -> Value {
    let product = model.value(2, ElementId::new(3, 3)).unwrap_or_default();
    let fingerprint = format!(
        "st2110|{}|{}",
        product["name"].as_str().unwrap_or("st2110"),
        product["revisionLevel"].as_str().unwrap_or(env!("CARGO_PKG_VERSION"))
    );
    let holders: Vec<Value> = model
        .role_paths()
        .into_iter()
        .filter(|(path, oid)| within(path, target, recurse) && (descriptors || !Model::is_class_manager(*oid)))
        .map(|(path, oid)| {
            let class = model.class_of(oid).expect("a class");
            let values: Vec<Value> = class
                .properties()
                .into_iter()
                .map(|p| {
                    json!({
                        "id": p.id.json(),
                        "descriptor": if descriptors { p.descriptor() } else { Value::Null },
                        "value": model.value(oid, p.id).unwrap_or(Value::Null),
                    })
                })
                .collect();
            json!({"path": path, "dependencyPaths": [], "allowedMembersClasses": [], "values": values,
                   "isRebuildable": false})
        })
        .collect();
    json!({"validationFingerprint": fingerprint, "values": holders})
}

fn notice(id: ElementId, name: &str, kind: u64, message: &str) -> Value {
    json!({"id": id.json(), "name": name, "noticeType": kind, "noticeMessage": message})
}

/// Checks a restore of a backup to the objects at and below `target`, and with `apply`
/// makes it: the `NcObjectPropertiesSetValidation` of each object in the restore scope
/// (IS-14 v1.0 Backup & restore: General concepts). `Err` for a request it cannot read.
fn restore(model: &mut Model, target: &[String], body: &Value, apply: bool) -> Result<Value, String> {
    let arguments = body.get("arguments").filter(|a| a.is_object()).ok_or("the body is {\"arguments\": {…}}")?;
    let holders = arguments["dataSet"]["values"].as_array().ok_or("arguments.dataSet.values is not a list")?;
    let recurse = match &arguments["recurse"] {
        Value::Null => true,
        value => value.as_bool().ok_or("arguments.recurse is true or false")?,
    };
    match arguments["restoreMode"].as_u64() {
        Some(0 | 1) => {}
        None if arguments["restoreMode"].is_null() => {}
        _ => return Err("arguments.restoreMode is 0 (Modify) or 1 (Rebuild)".into()),
    }
    let mut seen = Vec::new();
    let mut validations = Vec::new();
    for holder in holders {
        let path: Vec<String> = holder["path"]
            .as_array()
            .and_then(|p| p.iter().map(|r| r.as_str().map(str::to_string)).collect())
            .ok_or("each object's path is a list of roles")?;
        let values = holder["values"].as_array().ok_or("each object's values is a list")?;
        if seen.contains(&path) {
            return Err(format!("{} is in the backup twice", path.join(".")));
        }
        seen.push(path.clone());
        if !within(&path, target, recurse) {
            continue;
        }
        let Some(oid) = model.role_paths().into_iter().find(|(p, _)| *p == path).map(|(_, oid)| oid) else {
            validations.push(json!({"path": path, "status": NOT_FOUND, "notices": [],
                "statusMessage": "this Device has no such object, and none of its blocks can be rebuilt to hold one"}));
            continue;
        };
        let class = model.class_of(oid).expect("a class");
        let mut notices = Vec::new();
        let mut changes = Vec::new();
        for held in values {
            let id = ElementId::from_json(&held["id"]).ok_or("each property's id is {\"level\": …, \"index\": …}")?;
            let Some(p) = class.property(id) else {
                notices.push(notice(id, "unknown", WARNING, "the object has no such property; it is left out"));
                continue;
            };
            let value = held.get("value").cloned().unwrap_or(Value::Null);
            if p.read_only {
                notices.push(notice(id, p.name, WARNING, "Property is readonly"));
            } else if model.value(oid, id).as_ref() != Some(&value) {
                match model.refuse_set(oid, p, &value) {
                    Some(refused) => notices.push(notice(
                        id,
                        p.name,
                        ERROR,
                        refused["errorMessage"].as_str().unwrap_or("the value is refused"),
                    )),
                    None => changes.push((p.id, value)),
                }
            }
        }
        let failed = notices.iter().any(|n| n["noticeType"] == ERROR);
        let message = if failed {
            json!("some properties cannot be restored, so none of this object's are")
        } else if notices.is_empty() {
            Value::Null
        } else {
            json!("Some properties have notices")
        };
        if apply && !failed {
            for (id, value) in changes {
                model.command(oid, method::SET, &json!({"id": id.json(), "value": value}), now());
            }
        }
        validations.push(json!({"path": path, "status": if failed { FAILED } else { OK }, "notices": notices,
                                "statusMessage": message}));
    }
    Ok(json!(validations))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::node::connection::Side;
    use crate::node::monitor::Sync;
    use crate::node::ncp::Identity;

    fn model() -> Model {
        let identity = Identity {
            side: Side::Sender,
            label: "st2110 send test",
            device_id: "58f6b536-ca4c-43fd-880a-9df2501fc125",
            endpoint_id: "82fdc03f-76c7-4989-9d05-3ea2cc98875e",
            hostname: "test",
        };
        Model::new(&identity, &Sync::internal(), true, Instant::now())
    }

    fn request(method: &str, query: &str) -> Request {
        Request {
            method: method.into(),
            path: String::new(),
            query: query.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn call(model: &mut Model, method: &str, rest: &str, query: &str, body: Value) -> (u16, Value) {
        let response = route(model, &request(method, query), rest, &body);
        (response.status, serde_json::from_slice(&response.body).unwrap())
    }

    #[test]
    fn serves_the_device_model_by_role_path() {
        let mut m = model();
        assert_eq!(call(&mut m, "GET", "", "", Value::Null), (200, json!(["rolePaths/"])));
        let (_, paths) = call(&mut m, "GET", "/rolePaths", "", Value::Null);
        assert_eq!(paths, json!(["root/", "root.DeviceManager/", "root.ClassManager/", "root.sender-monitor/"]));
        let (_, below) = call(&mut m, "GET", "/rolePaths/root", "", Value::Null);
        assert_eq!(below, json!(["bulkProperties/", "descriptor/", "methods/", "properties/"]));
        let (_, properties) = call(&mut m, "GET", "/rolePaths/root/properties", "", Value::Null);
        assert_eq!(properties[0], "1p1/");
        assert_eq!(properties.as_array().unwrap().last().unwrap(), "2p2/");
        let (status, label) = call(&mut m, "GET", "/rolePaths/root/properties/1p6/value", "", Value::Null);
        assert_eq!((status, label), (200, json!({"status": 200, "value": "st2110 send test"})));
        let (_, descriptor) = call(&mut m, "GET", "/rolePaths/root.sender-monitor/descriptor", "", Value::Null);
        assert_eq!(descriptor["value"]["name"], "NcSenderMonitor");
        let (_, datatype) =
            call(&mut m, "GET", "/rolePaths/root.sender-monitor/properties/3p1/descriptor", "", Value::Null);
        assert_eq!(datatype["value"]["name"], "NcOverallStatus");
        // Set, and refused.
        let set = |m: &mut Model, id: &str, value: Value| {
            call(m, "PUT", &format!("/rolePaths/root/properties/{id}/value"), "", json!({"value": value}))
        };
        assert_eq!(set(&mut m, "1p6", json!("Booth")).0, 200);
        assert_eq!(set(&mut m, "1p5", json!("x")), (400, json!({"status": 405, "errorMessage": "role is read only"})));
        assert_eq!(set(&mut m, "9p9", json!("x")).0, 404);
        // Methods, by id.
        let (_, methods) = call(&mut m, "GET", "/rolePaths/root.ClassManager/methods", "", Value::Null);
        assert!(methods.as_array().unwrap().contains(&json!("3m1/")), "{methods}");
        let (status, class) = call(
            &mut m,
            "PATCH",
            "/rolePaths/root.ClassManager/methods/3m1",
            "",
            json!({"arguments": {"classId": [1, 2, 2, 2], "includeInherited": false}}),
        );
        assert_eq!((status, class["value"]["name"].clone()), (200, json!("NcSenderMonitor")));
        assert_eq!(call(&mut m, "PATCH", "/rolePaths/root/methods/9m9", "", json!({"arguments": {}})).0, 404);
        assert_eq!(call(&mut m, "GET", "/rolePaths/root.nothing", "", Value::Null).0, 404);
        assert_eq!(call(&mut m, "DELETE", "/rolePaths/root/bulkProperties", "", Value::Null).0, 400);
    }

    #[test]
    fn backs_up_and_restores() {
        let mut m = model();
        let (status, full) = call(&mut m, "GET", "/rolePaths/root/bulkProperties", "", Value::Null);
        assert_eq!(status, 200);
        let holders = full["value"]["values"].as_array().unwrap();
        assert_eq!(holders.len(), 4, "the whole model, the ClassManager with it");
        assert!(holders[0]["values"][0]["descriptor"].is_object());
        assert!(full["value"]["validationFingerprint"].as_str().unwrap().starts_with("st2110|st2110 send|"));
        let (_, lean) =
            call(&mut m, "GET", "/rolePaths/root/bulkProperties", "recurse=true&includeDescriptors=false", Value::Null);
        let lean = lean["value"].clone();
        let paths: Vec<&Value> = lean["values"].as_array().unwrap().iter().map(|h| &h["path"]).collect();
        assert_eq!(paths, [&json!(["root"]), &json!(["root", "DeviceManager"]), &json!(["root", "sender-monitor"])]);
        assert!(lean["values"][0]["values"][0]["descriptor"].is_null());
        let (_, one) = call(&mut m, "GET", "/rolePaths/root/bulkProperties", "recurse=false", Value::Null);
        assert_eq!(one["value"]["values"].as_array().unwrap().len(), 1);

        // Change the backup: the root's label and the monitor's reporting delay, an
        // object the Device does not have, and, separately, a value the monitor refuses.
        let mut changed = lean.clone();
        let set = |holder: &mut Value, id: (u16, u16), value: Value| {
            let held = holder["values"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["id"] == ElementId::new(id.0, id.1).json())
                .unwrap();
            held["value"] = value;
        };
        set(&mut changed["values"][0], (1, 6), json!("Restored"));
        set(&mut changed["values"][2], (3, 3), json!(7));
        changed["values"].as_array_mut().unwrap().push(json!({"path": ["root", "gain"], "values": []}));
        let body = json!({"arguments": {"dataSet": changed, "recurse": true, "restoreMode": 0}});
        // Validating changes nothing.
        let (status, checked) = call(&mut m, "PATCH", "/rolePaths/root/bulkProperties", "", body.clone());
        assert_eq!(status, 200);
        let statuses: Vec<&Value> = checked["value"].as_array().unwrap().iter().map(|v| &v["status"]).collect();
        assert_eq!(statuses, [&json!(200), &json!(200), &json!(200), &json!(404)]);
        assert!(checked["value"][0]["notices"].as_array().unwrap().iter().all(|n| n["noticeType"] == WARNING));
        let label =
            |m: &mut Model| call(m, "GET", "/rolePaths/root/properties/1p6/value", "", Value::Null).1["value"].clone();
        assert_eq!(label(&mut m), "st2110 send test");
        // Restoring makes the changes.
        let (_, restored) = call(&mut m, "PUT", "/rolePaths/root/bulkProperties", "", body);
        assert_eq!(restored["value"].as_array().unwrap().len(), 4);
        assert_eq!(label(&mut m), "Restored");
        let delay = call(&mut m, "GET", "/rolePaths/root.sender-monitor/properties/3p3/value", "", Value::Null).1;
        assert_eq!(delay["value"], 7);

        // A value refused fails its object, which keeps all of its values.
        let mut refused = lean.clone();
        set(&mut refused["values"][2], (3, 3), json!(-1));
        set(&mut refused["values"][2], (1, 6), json!("Not this"));
        let body = json!({"arguments": {"dataSet": refused, "recurse": true, "restoreMode": 1}});
        let (_, answer) = call(&mut m, "PUT", "/rolePaths/root.sender-monitor/bulkProperties", "", body);
        let answer = answer["value"].as_array().unwrap();
        assert_eq!(answer.len(), 1, "only the target's scope: {answer:?}");
        assert_eq!(answer[0]["status"], FAILED);
        assert!(
            answer[0]["notices"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["noticeType"] == ERROR && n["name"] == "statusReportingDelay")
        );
        let monitor_label =
            call(&mut m, "GET", "/rolePaths/root.sender-monitor/properties/1p6/value", "", Value::Null).1;
        assert_ne!(monitor_label["value"], "Not this");
        // A request it cannot read.
        let bad = json!({"arguments": {"dataSet": {}, "restoreMode": 0}});
        assert_eq!(call(&mut m, "PUT", "/rolePaths/root/bulkProperties", "", bad).0, 400);
        let mode = json!({"arguments": {"dataSet": {"values": []}, "restoreMode": 2}});
        assert_eq!(call(&mut m, "PATCH", "/rolePaths/root/bulkProperties", "", mode).0, 400);
    }
}
