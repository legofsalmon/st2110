//! A Sender's or Receiver's `/constraints`: what each transport parameter may be set to.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What each transport parameter may be set to, one map per leg: two for an ST 2022-7
/// Receiver, one otherwise. A parameter a leg does not list is one it does not have
/// (IS-05 v1.2 constraints-schema-rtp.json: "every transport parameter must have an
/// entry").
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Constraints {
    /// The legs, path 1 first.
    pub legs: Vec<BTreeMap<String, Constraint>>,
}

/// What one transport parameter may be set to (IS-05 v1.2 constraint-schema.json).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    /// The values it may take.
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    /// The least number it may be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    /// The greatest number it may be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    /// A regular expression its value matches. It is left to the Connection API to
    /// check, as it does every request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// What the constraint is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Constraints {
    /// Reads the JSON a `/constraints` endpoint returns.
    pub fn from_json(value: &Value) -> Result<Self, String> {
        Self::deserialize(value).map_err(|e| format!("not IS-05 constraints: {e}"))
    }

    /// Whether leg `leg` (counting from 0) has the parameter `name`.
    pub fn has(&self, leg: usize, name: &str) -> bool {
        self.legs.get(leg).is_some_and(|params| params.contains_key(name))
    }

    /// Why leg `leg` (counting from 0) does not allow `value` for the parameter `name`,
    /// or `None` when it does.
    pub fn check(&self, leg: usize, name: &str, value: &Value) -> Option<String> {
        let Some(params) = self.legs.get(leg) else {
            return Some(format!("there is no leg {}", leg + 1));
        };
        let Some(constraint) = params.get(name) else {
            return Some(format!("there is no {name} parameter"));
        };
        constraint.check(value).map(|why| format!("{name} {why}"))
    }
}

impl Constraint {
    /// Why `value` breaks this constraint, or `None` when it does not. A `pattern` is not
    /// checked.
    pub fn check(&self, value: &Value) -> Option<String> {
        if let Some(values) = &self.values
            && !values.iter().any(|allowed| same(allowed, value))
        {
            let shown: Vec<String> = values.iter().take(10).map(show).collect();
            let more = values.len().saturating_sub(shown.len());
            let list = if more == 0 { shown.join(", ") } else { format!("{} and {more} more", shown.join(", ")) };
            return Some(format!("{} is not one of {list}", show(value)));
        }
        let number = value.as_f64()?;
        if let Some(minimum) = self.minimum
            && number < minimum
        {
            return Some(format!("{} is below the minimum, {minimum}", show(value)));
        }
        if let Some(maximum) = self.maximum
            && number > maximum
        {
            return Some(format!("{} is above the maximum, {maximum}", show(value)));
        }
        None
    }
}

/// Whether two parameter values are the same: numbers by value, addresses as addresses
/// (`2001:0db8::1` is `2001:db8::1`), and anything else exactly.
pub(crate) fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::String(x), Value::String(y)) => match (x.parse::<IpAddr>(), y.parse::<IpAddr>()) {
            (Ok(x), Ok(y)) => x == y,
            _ => x == y,
        },
        _ => a == b,
    }
}

/// A value as a message shows it: strings without quotes.
pub(crate) fn show(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The ST 2022-7 example from IS-05 v1.2, cut down to the core parameters.
    fn example() -> Constraints {
        Constraints::from_json(&json!([
            {
                "source_ip": {}, "multicast_ip": {},
                "interface_ip": {"enum": ["192.168.7.2", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"]},
                "destination_port": {"minimum": 5000, "maximum": 49150}, "rtp_enabled": {}
            },
            {
                "source_ip": {}, "multicast_ip": {}, "interface_ip": {"enum": ["192.168.8.5"]},
                "destination_port": {"minimum": 5000, "maximum": 49150}, "rtp_enabled": {"enum": [true]},
                "ext_vendor_thing": {"pattern": "^[a-z]+$", "description": "a vendor's own"}
            }
        ]))
        .expect("constraints")
    }

    #[test]
    fn checks_enums_and_ranges() {
        let c = example();
        assert_eq!(c.legs.len(), 2);
        assert_eq!(c.check(0, "destination_port", &json!(5004)), None);
        assert_eq!(
            c.check(0, "destination_port", &json!(4999)).as_deref(),
            Some("destination_port 4999 is below the minimum, 5000")
        );
        assert_eq!(
            c.check(1, "destination_port", &json!(65000)).as_deref(),
            Some("destination_port 65000 is above the maximum, 49150")
        );
        // Addresses match as addresses, however they are written.
        assert_eq!(c.check(0, "interface_ip", &json!("2001:db8:85a3::8a2e:370:7334")), None);
        assert_eq!(
            c.check(1, "interface_ip", &json!("192.168.7.2")).as_deref(),
            Some("interface_ip 192.168.7.2 is not one of 192.168.8.5")
        );
        assert_eq!(c.check(1, "rtp_enabled", &json!(true)), None);
        assert_eq!(c.check(1, "rtp_enabled", &json!(false)).as_deref(), Some("rtp_enabled false is not one of true"));
        // A string is no number to compare with a range; a pattern is not checked.
        assert_eq!(c.check(0, "destination_port", &json!("auto")), None);
        assert_eq!(c.check(1, "ext_vendor_thing", &json!("NOT LOWER CASE")), None);
        assert_eq!(c.check(0, "fec_enabled", &json!(true)).as_deref(), Some("there is no fec_enabled parameter"));
        assert_eq!(c.check(2, "rtp_enabled", &json!(true)).as_deref(), Some("there is no leg 3"));
        assert!(c.has(0, "multicast_ip") && !c.has(0, "fec_mode") && !c.has(5, "multicast_ip"));
    }

    #[test]
    fn long_enums_are_cut_short() {
        let c = Constraint { values: Some((0..15).map(|i| json!(i)).collect()), ..Constraint::default() };
        assert_eq!(c.check(&json!(15)).as_deref(), Some("15 is not one of 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 and 5 more"));
        assert_eq!(c.check(&json!(3.0)), None, "numbers match by value");
    }

    #[test]
    fn reads_what_the_schema_allows_and_rejects_the_rest() {
        assert_eq!(Constraints::from_json(&json!([])).unwrap().legs.len(), 0);
        assert!(Constraints::from_json(&json!({"source_ip": {}})).unwrap_err().starts_with("not IS-05 constraints"));
        assert!(Constraints::from_json(&json!([{"destination_port": {"minimum": "5000"}}])).is_err());
        let round_trip = serde_json::to_value(example()).unwrap();
        assert_eq!(round_trip[0]["destination_port"], json!({"minimum": 5000.0, "maximum": 49150.0}));
        assert_eq!(Constraints::from_json(&round_trip).unwrap(), example());
    }
}
