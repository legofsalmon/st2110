//! BCP-004-01 Receiver capabilities: whether a Sender's stream satisfies a Receiver's
//! constraint sets.
//!
//! Each parameter constraint targets a Flow, Source or Sender attribute, or an SDP
//! parameter, as the Capabilities register in the NMOS Parameter Registers defines.
//! A constraint whose target is unknown or absent cannot be evaluated and is skipped;
//! a constraint set with nothing left to evaluate is satisfied (BCP-004-01, Behaviour:
//! Controllers).

use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;
use st2110_sdp::Rational;

use crate::model::{Component, Flow, Sender, Source, short_urn};

/// What the Sender's SDP file adds to the stream's description.
#[derive(Debug, Default)]
pub(crate) struct SdpFacts {
    /// `sampling`, from the first stream.
    pub sampling: Option<String>,
    /// `TP`, from the first stream.
    pub tp: Option<String>,
    /// `a=ptime`, in milliseconds.
    pub ptime: Option<f64>,
    /// `a=maxptime`, in milliseconds.
    pub maxptime: Option<f64>,
    /// `b=AS`, in kbit/s.
    pub bandwidth: Option<u64>,
}

impl SdpFacts {
    /// Reads the attributes of the first media section, or the session's.
    pub fn read(text: &str, first_stream: Option<&st2110_sdp::Stream>) -> Self {
        let (sdp, _) = st2110_sdp::parse(text);
        let media = sdp.media.first();
        let attribute = |name: &str| {
            media.and_then(|m| m.attribute(name)).or_else(|| sdp.session.attribute(name)).and_then(|a| a.value)
        };
        let millis = |name: &str| attribute(name).and_then(|v| v.trim().parse::<f64>().ok());
        let bandwidth = media
            .into_iter()
            .chain([&sdp.session])
            .flat_map(|section| section.fields_of('b'))
            .filter_map(|field| st2110_sdp::parse_bandwidth(&field.value).ok())
            .find(|(kind, _)| kind.eq_ignore_ascii_case("AS"))
            .map(|(_, kbps)| kbps);
        let param = |name: &str| first_stream?.parameters.iter().find(|p| p.name == name).and_then(|p| p.value.clone());
        Self {
            sampling: param("sampling"),
            tp: param("TP"),
            ptime: millis("ptime"),
            maxptime: millis("maxptime"),
            bandwidth,
        }
    }
}

/// A Sender's stream, as the constraints see it.
pub(crate) struct StreamFacts<'m, 'a> {
    pub flow: &'m Flow<'a>,
    pub source: Option<&'m Source<'a>>,
    pub sender: &'m Sender<'a>,
    pub sdp: Option<&'m SdpFacts>,
}

/// The value a constraint is compared against.
#[derive(Clone, Debug, PartialEq)]
enum Target {
    Str(String),
    Int(i64),
    Num(f64),
    Rat(i64, i64),
    Bool(bool),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => f.write_str(s),
            Self::Int(n) => write!(f, "{n}"),
            Self::Num(n) => write!(f, "{n}"),
            Self::Rat(n, 1) => write!(f, "{n}"),
            Self::Rat(n, d) => write!(f, "{n}/{d}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

fn rational(r: Rational) -> Option<Target> {
    Some(Target::Rat(i64::try_from(r.numerator()).ok()?, i64::try_from(r.denominator()).ok()?))
}

fn int(n: u64) -> Option<Target> {
    i64::try_from(n).ok().map(Target::Int)
}

/// The stream's value for a parameter constraint, or `None` when it cannot be evaluated.
fn target(urn: &str, s: &StreamFacts<'_, '_>) -> Option<Target> {
    let flow = s.flow;
    let video = flow.format.map(short_urn) == Some("video");
    let text = |t: &str| Some(Target::Str(t.to_string()));
    match urn.strip_prefix("urn:x-nmos:cap:")? {
        "format:media_type" => text(flow.media_type?),
        "format:grain_rate" => rational(flow.grain_rate.or_else(|| s.source?.grain_rate)?),
        "format:frame_width" => int(flow.frame_width?),
        "format:frame_height" => int(flow.frame_height?),
        "format:interlace_mode" => text(flow.interlace_mode.or(video.then_some("progressive"))?),
        "format:colorspace" => text(flow.colorspace?),
        "format:transfer_characteristic" => text(flow.transfer_characteristic.or(video.then_some("SDR"))?),
        "format:color_sampling" => match s.sdp.and_then(|sdp| sdp.sampling.clone()) {
            Some(sampling) => Some(Target::Str(sampling)),
            None => text(&sampling(&flow.components)?),
        },
        "format:component_depth" => int(component_depth(&flow.components)?),
        "format:bit_rate" => int(flow.bit_rate?),
        "format:profile" => text(flow.profile?),
        "format:level" => text(flow.level?),
        "format:sublevel" => text(flow.sublevel?),
        "format:channel_count" => int(u64::try_from(s.source?.channels?).ok()?),
        "format:sample_rate" => rational(flow.sample_rate?),
        "format:sample_depth" => int(flow.bit_depth?),
        "transport:bit_rate" => int(s.sender.bit_rate?),
        "transport:packet_time" => Some(Target::Num(s.sdp?.ptime?)),
        "transport:max_packet_time" => Some(Target::Num(s.sdp?.maxptime?)),
        "transport:st2110_21_sender_type" => text(s.sender.st2110_21_sender_type.or_else(|| s.sdp?.tp.as_deref())?),
        "transport:packet_transmission_mode" => {
            let jpeg_xs = flow.media_type.is_some_and(|m| m.eq_ignore_ascii_case("video/jxsv"));
            text(s.sender.packet_transmission_mode.or(jpeg_xs.then_some("codestream"))?)
        }
        "transport:hkep" => Some(Target::Bool(s.sender.hkep?)),
        "transport:privacy" => Some(Target::Bool(s.sender.privacy?)),
        // Event types may use wildcards (IS-07), which this does not evaluate.
        _ => None,
    }
}

/// Checks a Receiver's `constraint_sets` against a stream. On failure, gives one reason
/// per enabled constraint set.
pub(crate) fn evaluate(sets: &[Value], stream: &StreamFacts<'_, '_>) -> Result<(), Vec<String>> {
    let mut reasons = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        let Some(set) = set.as_object() else {
            reasons.push(format!("constraint set {} is not an object", i + 1));
            continue;
        };
        if set.get("urn:x-nmos:cap:meta:enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        let name = match set.get("urn:x-nmos:cap:meta:label").and_then(Value::as_str) {
            Some(label) => format!("\"{label}\""),
            None => format!("set {}", i + 1),
        };
        let failure =
            set.iter().filter(|(urn, _)| !urn.starts_with("urn:x-nmos:cap:meta:")).find_map(|(urn, constraint)| {
                let value = target(urn, stream)?;
                satisfies(constraint, &value).err().map(|why| format!("{} {value} {why}", short_urn(urn)))
            });
        match failure {
            None => return Ok(()),
            Some(why) => reasons.push(format!("{name}: {why}")),
        }
    }
    if reasons.is_empty() {
        reasons.push(if sets.is_empty() {
            "the list of constraint sets is empty".to_string()
        } else {
            "every constraint set is disabled".to_string()
        });
    }
    Err(reasons)
}

/// Checks one parameter constraint; on failure says why, as the end of a sentence.
fn satisfies(constraint: &Value, value: &Target) -> Result<(), String> {
    let Some(keywords) = constraint.as_object() else {
        return Err("cannot be checked: the constraint is not an object".into());
    };
    if let Some(allowed) = keywords.get("enum") {
        let Some(allowed) = allowed.as_array() else {
            return Err("cannot be checked: its enum is not an array".into());
        };
        if !allowed.iter().any(|a| equal(a, value)) {
            let list: Vec<String> = allowed.iter().map(show).collect();
            return Err(format!("is not one of {}", list.join(", ")));
        }
    }
    if let Some(minimum) = keywords.get("minimum")
        && compare(value, minimum) == Some(Ordering::Less)
    {
        return Err(format!("is below the minimum {}", show(minimum)));
    }
    if let Some(maximum) = keywords.get("maximum")
        && compare(value, maximum) == Some(Ordering::Greater)
    {
        return Err(format!("is above the maximum {}", show(maximum)));
    }
    Ok(())
}

/// Reads a JSON rational with its denominator made positive.
fn json_rational(value: &Value) -> Option<(i64, i64)> {
    let o = value.as_object()?;
    let num = o.get("numerator")?.as_i64()?;
    let den = match o.get("denominator") {
        None => 1,
        Some(d) => d.as_i64()?,
    };
    match den.cmp(&0) {
        Ordering::Equal => None,
        Ordering::Less => Some((num.checked_neg()?, den.checked_neg()?)),
        Ordering::Greater => Some((num, den)),
    }
}

/// Compares rationals by cross-multiplication (BCP-004-01, Rational Constraint Keywords).
fn compare_rational((n1, d1): (i64, i64), (n2, d2): (i64, i64)) -> Ordering {
    (i128::from(n1) * i128::from(d2)).cmp(&(i128::from(n2) * i128::from(d1)))
}

fn equal(allowed: &Value, value: &Target) -> bool {
    match value {
        Target::Str(s) => allowed.as_str() == Some(s),
        Target::Bool(b) => allowed.as_bool() == Some(*b),
        Target::Int(_) | Target::Num(_) | Target::Rat(..) => compare(value, allowed) == Some(Ordering::Equal),
    }
}

/// Orders a value against a constraint's number or rational; `None` when they do not compare.
fn compare(value: &Target, bound: &Value) -> Option<Ordering> {
    match value {
        Target::Int(n) => match bound.as_i64() {
            Some(b) => Some(n.cmp(&b)),
            None => (*n as f64).partial_cmp(&bound.as_f64()?),
        },
        Target::Num(n) => {
            let b = bound.as_f64()?;
            // Packet times such as 0.125 ms come from decimal text on both sides.
            if (n - b).abs() <= 1e-9 * b.abs().max(1.0) { Some(Ordering::Equal) } else { n.partial_cmp(&b) }
        }
        Target::Rat(n, d) => Some(compare_rational((*n, *d), json_rational(bound)?)),
        Target::Str(_) | Target::Bool(_) => None,
    }
}

/// A constraint value as a person would write it: `30000/1001`, not JSON.
fn show(value: &Value) -> String {
    match (value.as_str(), json_rational(value)) {
        (Some(s), _) => s.to_string(),
        (None, Some((n, 1))) => n.to_string(),
        (None, Some((n, d))) => format!("{n}/{d}"),
        (None, None) => value.to_string(),
    }
}

/// The ST 2110-20 `sampling` a raw video Flow's components describe, when they
/// describe one. `YCbCr` also stands for `CLYCbCr`, which the components cannot tell apart.
pub(crate) fn sampling(components: &[Component<'_>]) -> Option<String> {
    let find = |name: &str| components.iter().find(|c| c.name == name);
    let subsampled = |luma: &Component<'_>, chroma: &Component<'_>| {
        let (lw, lh, cw, ch) = (luma.width?, luma.height?, chroma.width?, chroma.height?);
        match (cw.saturating_mul(2) == lw, ch.saturating_mul(2) == lh, cw == lw, ch == lh) {
            (_, _, true, true) => Some("4:4:4"),
            (true, _, _, true) => Some("4:2:2"),
            (true, true, _, _) => Some("4:2:0"),
            _ => None,
        }
    };
    let names: Vec<&str> = components.iter().map(|c| c.name).collect();
    let has = |set: &[&str]| set.iter().all(|n| names.contains(n)) && names.len() == set.len();
    if has(&["Y", "Cb", "Cr"]) {
        return Some(format!("YCbCr-{}", subsampled(find("Y")?, find("Cb")?)?));
    }
    if has(&["I", "Ct", "Cp"]) {
        return Some(format!("ICtCp-{}", subsampled(find("I")?, find("Ct")?)?));
    }
    if has(&["R", "G", "B"]) {
        return Some("RGB".into());
    }
    if has(&["A"]) {
        return Some("KEY".into());
    }
    None
}

/// The bit depth every component shares.
pub(crate) fn component_depth(components: &[Component<'_>]) -> Option<u64> {
    let first = components.first()?.bit_depth?;
    components.iter().all(|c| c.bit_depth == Some(first)).then_some(first)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn component(name: &str, width: u64, height: u64) -> Component<'_> {
        Component { name, width: Some(width), height: Some(height), bit_depth: Some(10) }
    }

    #[test]
    fn sampling_from_components() {
        let yuv = |cw, ch| vec![component("Y", 1920, 1080), component("Cb", cw, ch), component("Cr", cw, ch)];
        assert_eq!(sampling(&yuv(960, 1080)).as_deref(), Some("YCbCr-4:2:2"));
        assert_eq!(sampling(&yuv(960, 540)).as_deref(), Some("YCbCr-4:2:0"));
        assert_eq!(sampling(&yuv(1920, 1080)).as_deref(), Some("YCbCr-4:4:4"));
        assert_eq!(sampling(&yuv(640, 1080)), None);
        let rgb = [component("R", 8, 8), component("G", 8, 8), component("B", 8, 8)];
        assert_eq!(sampling(&rgb).as_deref(), Some("RGB"));
        assert_eq!(sampling(&[component("A", 8, 8)]).as_deref(), Some("KEY"));
        assert_eq!(sampling(&[component("Y", 8, 8)]), None);
    }

    #[test]
    fn keywords() {
        let rate = Target::Rat(30000, 1001);
        assert!(satisfies(&json!({}), &rate).is_ok());
        assert!(satisfies(&json!({"enum": [{"numerator": 60000, "denominator": 2002}]}), &rate).is_ok());
        assert_eq!(
            satisfies(&json!({"enum": [{"numerator": 25}, {"numerator": 50}]}), &rate),
            Err("is not one of 25, 50".into())
        );
        assert!(satisfies(&json!({"minimum": {"numerator": 25}, "maximum": {"numerator": 30}}), &rate).is_ok());
        assert_eq!(
            satisfies(&json!({"maximum": {"numerator": -25, "denominator": -1}}), &rate),
            Err("is above the maximum 25".into())
        );
        let width = Target::Int(1920);
        assert!(satisfies(&json!({"enum": [1280, 1920]}), &width).is_ok());
        assert_eq!(satisfies(&json!({"maximum": 1280}), &width), Err("is above the maximum 1280".into()));
        assert!(satisfies(&json!({"enum": [0.125, 1]}), &Target::Num(0.125)).is_ok());
        assert!(satisfies(&json!({"enum": ["video/raw"]}), &Target::Str("video/raw".into())).is_ok());
        assert!(satisfies(&json!({"enum": [true]}), &Target::Bool(false)).is_err());
        assert!(satisfies(&json!("video/raw"), &width).is_err());
    }
}
