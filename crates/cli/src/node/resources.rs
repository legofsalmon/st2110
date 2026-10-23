//! The IS-04 v1.3 resources of a Node of this program's own: the Node, its one Device,
//! and a Source, Flow and Sender that describe the stream it sends, or a Receiver.

use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

use serde_json::{Value, json};
use st2110_media::describe::{Clock, Description, Media};
use st2110_media::format::{Scan, VideoFormat};
use st2110_sdp::video::{Depth, Sampling};

const VIDEO: &str = "urn:x-nmos:format:video";
const AUDIO: &str = "urn:x-nmos:format:audio";

/// The version of the Connection API the Node serves.
pub(crate) const CONNECTION_VERSION: &str = "v1.2";

/// The resources' ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ids {
    pub node: String,
    pub device: String,
    pub source: String,
    pub flow: String,
    /// The Sender's or the Receiver's.
    pub endpoint: String,
}

impl Ids {
    /// Ids that stay the same from one run to the next for the same `seed`, such as
    /// the machine's name and where it sends, so that a controller that knew the Sender
    /// before a restart knows it after (IS-04 v1.3 Identifiers). They are laid out as
    /// version 4 UUIDs, which IS-04's schemas take, though they are not random.
    pub(crate) fn from_seed(seed: &str) -> Self {
        let id = |kind: &str| {
            let half = |n: u8| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                (seed, kind, n).hash(&mut hasher);
                hasher.finish()
            };
            let (high, low) = (half(0), half(1));
            let high = (high & !0xF000) | 0x4000;
            let low = (low & !(0xC << 60)) | (0x8 << 60);
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                high >> 32,
                (high >> 16) & 0xFFFF,
                high & 0xFFFF,
                low >> 48,
                low & 0xFFFF_FFFF_FFFF
            )
        };
        Self {
            node: id("node"),
            device: id("device"),
            source: id("source"),
            flow: id("flow"),
            endpoint: id("endpoint"),
        }
    }
}

/// Where the Node is: its address, the port its APIs are on, its name, and its network
/// interfaces, each a name and a MAC address; whether its APIs ask for an IS-10 token,
/// and whether they are served over TLS.
#[derive(Clone, Debug)]
pub(crate) struct Place {
    pub host: Ipv4Addr,
    pub port: u16,
    pub hostname: String,
    pub interfaces: Vec<(String, String)>,
    pub authorization: bool,
    pub secure: bool,
}

impl Place {
    /// Where the APIs are: `http://` or, over TLS, `https://`.
    fn base(&self) -> String {
        format!("{}://{}:{}", self.protocol(), self.host, self.port)
    }

    /// The protocol of the Node API's endpoint (IS-04 v1.3 APIs: Node API, `api`).
    fn protocol(&self) -> &'static str {
        if self.secure { "https" } else { "http" }
    }
}

/// What every IS-04 resource has.
fn core(id: &str, version: &str, label: &str) -> Value {
    json!({"id": id, "version": version, "label": label, "description": label, "tags": {}})
}

fn merge(mut base: Value, more: Value) -> Value {
    if let (Some(base), Value::Object(more)) = (base.as_object_mut(), more) {
        base.extend(more);
    }
    base
}

/// The Node's clock, from the stream's reference clock: PTP from a named grandmaster,
/// taken as locked since the system clock is said to follow it, or the machine's own
/// clock, which is all `traceable` and `localmac=` say of it.
fn clock(reference: Option<&Clock>) -> Value {
    match reference {
        Some(Clock::Ptp { grandmaster, .. }) => json!({
            "name": "clk0", "ref_type": "ptp", "traceable": false, "version": "IEEE1588-2008",
            "gmid": grandmaster.to_string().to_ascii_lowercase(), "locked": true,
        }),
        _ => json!({"name": "clk0", "ref_type": "internal"}),
    }
}

/// The Node. It sends no LLDP, so its interfaces' `chassis_id` is null, and it knows
/// nothing of the switch ports they are plugged into.
pub(crate) fn node(ids: &Ids, place: &Place, version: &str, label: &str, reference: Option<&Clock>) -> Value {
    let interfaces: Vec<Value> =
        place.interfaces.iter().map(|(name, mac)| json!({"chassis_id": null, "port_id": mac, "name": name})).collect();
    merge(
        core(&ids.node, version, label),
        json!({
            "href": format!("{}/", place.base()), "hostname": place.hostname,
            "api": {"versions": ["v1.3"], "endpoints": [
                {"host": place.host.to_string(), "port": place.port, "protocol": place.protocol(), "authorization": place.authorization},
            ]},
            // IS-13 (v1.0 draft): the Annotation API, on the Node's own port.
            "caps": {}, "services": [{
                "href": format!("{}/x-nmos/annotation/{}/", place.base(), st2110_nmos::annotation::VERSION),
                "type": st2110_nmos::annotation::SERVICE_TYPE, "authorization": place.authorization,
            }],
            "clocks": [clock(reference)], "interfaces": interfaces,
        }),
    )
}

/// The Device, whose Connection API is the Node's.
pub(crate) fn device(ids: &Ids, place: &Place, version: &str, label: &str) -> Value {
    merge(
        core(&ids.device, version, label),
        json!({
            "type": "urn:x-nmos:device:generic", "node_id": ids.node, "senders": [], "receivers": [],
            "controls": [{
                "href": format!("{}/x-nmos/connection/{CONNECTION_VERSION}/", place.base()),
                "type": format!("urn:x-nmos:control:sr-ctrl/{CONNECTION_VERSION}"),
                "authorization": place.authorization,
            }, {
                // IS-12 v1.0.1: the Device's control model, with its status monitor.
                "href": format!("{}://{}:{}{}/", if place.secure { "wss" } else { "ws" }, place.host, place.port, super::ncp::PATH),
                "type": st2110_nmos::ncp::CONTROL_TYPE, "authorization": place.authorization,
            }, {
                // IS-14 v1.0: the same model by role path over HTTP, with backup and restore.
                "href": format!("{}/x-nmos/configuration/{}/", place.base(), super::configuration::VERSION),
                "type": super::configuration::CONTROL_TYPE, "authorization": place.authorization,
            }],
        }),
    )
}

fn rational(rate: st2110_sdp::Rational) -> Value {
    json!({"numerator": rate.numerator(), "denominator": rate.denominator()})
}

/// The components of a picture of `format`, as a Flow lists them.
fn components(format: &VideoFormat) -> Vec<Value> {
    let (w, h) = (format.width, format.height);
    let depth = match format.depth {
        Depth::Bits8 => 8,
        Depth::Bits10 => 10,
        Depth::Bits12 => 12,
        Depth::Bits16 | Depth::Bits16Float => 16,
    };
    let (names, chroma): ([&str; 3], (u32, u32)) = match format.sampling {
        Sampling::YCbCr444 | Sampling::ClYCbCr444 => (["Y", "Cb", "Cr"], (w, h)),
        Sampling::YCbCr422 | Sampling::ClYCbCr422 => (["Y", "Cb", "Cr"], (w / 2, h)),
        Sampling::YCbCr420 | Sampling::ClYCbCr420 => (["Y", "Cb", "Cr"], (w / 2, h / 2)),
        Sampling::ICtCp444 => (["I", "Ct", "Cp"], (w, h)),
        Sampling::ICtCp422 => (["I", "Ct", "Cp"], (w / 2, h)),
        Sampling::ICtCp420 => (["I", "Ct", "Cp"], (w / 2, h / 2)),
        Sampling::Rgb => (["R", "G", "B"], (w, h)),
        Sampling::Xyz => (["X", "Y", "Z"], (w, h)),
        Sampling::Key => return vec![json!({"name": "A", "width": w, "height": h, "bit_depth": depth})],
    };
    names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let (width, height) = if i == 0 { (w, h) } else { chroma };
            json!({"name": name, "width": width, "height": height, "bit_depth": depth})
        })
        .collect()
}

/// The Source and the Flow of the stream a Sender sends.
pub(crate) fn source_and_flow(ids: &Ids, version: &str, label: &str, description: &Description) -> (Value, Value) {
    let common = json!({"device_id": ids.device, "parents": []});
    let (source, flow) = match &description.media {
        Media::Video(format) => {
            let mode = match format.scan {
                Scan::Progressive => "progressive",
                Scan::Interlaced => "interlaced_tff",
                Scan::Segmented => "interlaced_psf",
            };
            (
                json!({"format": VIDEO, "grain_rate": rational(format.rate)}),
                json!({
                    "format": VIDEO, "grain_rate": rational(format.rate), "media_type": "video/raw",
                    "frame_width": format.width, "frame_height": format.height, "interlace_mode": mode,
                    "colorspace": format.colorimetry, "transfer_characteristic": format.transfer,
                    "components": components(format),
                }),
            )
        }
        Media::Audio(format) => {
            let channels: Vec<Value> = (1..=format.channels)
                .map(|n| match (format.channels, n) {
                    (2, 1) => json!({"label": "Left", "symbol": "L"}),
                    (2, _) => json!({"label": "Right", "symbol": "R"}),
                    (1, _) => json!({"label": "Mono", "symbol": "M"}),
                    _ => json!({"label": format!("Channel {n}"), "symbol": format!("U{n:02}")}),
                })
                .collect();
            let sample_rate = json!({"numerator": format.sample_rate, "denominator": 1});
            let flow = if format.aes3 {
                // AM824 is coded audio, with no bit depth of its own (IS-04 flow_audio_coded).
                json!({"format": AUDIO, "sample_rate": sample_rate, "media_type": "audio/AM824"})
            } else {
                json!({"format": AUDIO, "sample_rate": sample_rate, "media_type": format!("audio/{}", format.encoding()),
                       "bit_depth": format.bits})
            };
            (json!({"format": AUDIO, "channels": channels}), flow)
        }
    };
    let source = merge(
        merge(merge(core(&ids.source, version, label), json!({"caps": {}, "clock_name": "clk0"})), common.clone()),
        source,
    );
    let flow = merge(merge(merge(core(&ids.flow, version, label), json!({"source_id": ids.source})), common), flow);
    (source, flow)
}

/// The transport of a Sender that sends to `multicast` addresses or not.
pub(crate) fn sender_transport(multicast: bool) -> &'static str {
    if multicast { "urn:x-nmos:transport:rtp.mcast" } else { "urn:x-nmos:transport:rtp.ucast" }
}

/// The Sender, sending on `bindings`, the interface of each leg.
pub(crate) fn sender(
    ids: &Ids,
    place: &Place,
    version: &str,
    label: &str,
    description: &Description,
    bindings: &[String],
    enabled: bool,
) -> Value {
    let multicast = description.legs.first().is_some_and(|l| l.destination.ip().is_multicast());
    let mut sender = merge(
        core(&ids.endpoint, version, label),
        json!({
            "caps": {}, "flow_id": ids.flow, "transport": sender_transport(multicast), "device_id": ids.device,
            "manifest_href": format!(
                "{}/x-nmos/connection/{CONNECTION_VERSION}/single/senders/{}/transportfile", place.base(), ids.endpoint
            ),
            "interface_bindings": bindings, "subscription": {"receiver_id": null, "active": enabled},
        }),
    );
    if let Media::Video(format) = &description.media {
        sender["st2110_21_sender_type"] = json!(format.sender_type.as_str());
    }
    sender
}

/// The Receiver, of video or audio, on `bindings`, the interface of each leg, taking a
/// stream or not.
pub(crate) fn receiver(ids: &Ids, version: &str, label: &str, video: bool, bindings: &[String], active: bool) -> Value {
    let (format, media_types) =
        if video { (VIDEO, json!(["video/raw"])) } else { (AUDIO, json!(["audio/L24", "audio/L16", "audio/AM824"])) };
    merge(
        core(&ids.endpoint, version, label),
        json!({
            "device_id": ids.device, "transport": "urn:x-nmos:transport:rtp", "interface_bindings": bindings,
            "subscription": {"sender_id": null, "active": active}, "format": format,
            "caps": {"media_types": media_types},
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use st2110_media::describe::Leg;
    use st2110_media::format::AudioFormat;
    use st2110_nmos::{Manifest, Snapshot};

    fn place() -> Place {
        Place {
            host: Ipv4Addr::new(192, 168, 10, 21),
            port: 8080,
            hostname: "studio-mac".into(),
            interfaces: vec![("en0".into(), "02-00-c0-a8-0a-15".into())],
            authorization: false,
            secure: false,
        }
    }

    #[test]
    fn gives_https_and_wss_over_tls() {
        let ids = Ids::from_seed("test");
        let secure = Place { secure: true, authorization: true, ..place() };
        let node = node(&ids, &secure, "1:0", "studio-mac", None);
        assert_eq!(node["href"], "https://192.168.10.21:8080/");
        assert_eq!(node["api"]["endpoints"][0]["protocol"], "https");
        assert_eq!(node["api"]["endpoints"][0]["authorization"], true);
        let device = device(&ids, &secure, "1:0", "test");
        assert_eq!(device["controls"][0]["href"], "https://192.168.10.21:8080/x-nmos/connection/v1.2/");
        assert_eq!(device["controls"][1]["href"], "wss://192.168.10.21:8080/x-nmos/ncp/v1.0/");
        let plain = super::device(&ids, &place(), "1:0", "test");
        assert_eq!(plain["controls"][1]["href"], "ws://192.168.10.21:8080/x-nmos/ncp/v1.0/");
        assert_eq!(device["controls"][2]["href"], "https://192.168.10.21:8080/x-nmos/configuration/v1.0/");
        assert_eq!(device["controls"][2]["type"], "urn:x-nmos:control:configuration/v1.0");
        let service = &node["services"][0];
        assert_eq!(service["href"], "https://192.168.10.21:8080/x-nmos/annotation/v1.0/");
        assert_eq!(st2110_nmos::annotation::service_href(&node).as_deref(), service["href"].as_str());
    }

    #[test]
    fn ids_stay_the_same_and_are_uuids() {
        let ids = Ids::from_seed("studio-mac send 239.1.1.1:5004");
        assert_eq!(ids, Ids::from_seed("studio-mac send 239.1.1.1:5004"));
        assert_ne!(ids.node, Ids::from_seed("studio-mac send 239.1.1.2:5004").node);
        for id in [&ids.node, &ids.device, &ids.source, &ids.flow, &ids.endpoint] {
            let parts: Vec<&str> = id.split('-').collect();
            assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12], "{id}");
            assert!(parts[2].starts_with('4') && "89ab".contains(&parts[3][..1]), "{id}");
        }
    }

    /// The resources of a Sender of `media`, with its SDP file, pass the registry check.
    fn check(media: Media) {
        let description = Description {
            name: "st2110 test".into(),
            media,
            payload_type: 96,
            legs: vec![Leg {
                destination: "239.1.1.1:5004".parse().unwrap(),
                source: Some(Ipv4Addr::new(192, 168, 10, 21)),
            }],
            clock: Clock::parse("08-00-11-FF-FE-21-E1-B0:127").ok(),
            ttl: 32,
            rtp_offset: 0,
        };
        let (ids, place, version) = (Ids::from_seed("test"), place(), "1790510437:0");
        let (source, flow) = source_and_flow(&ids, version, "test", &description);
        let sender = sender(&ids, &place, version, "test", &description, &["en0".into()], true);
        let href = sender["manifest_href"].as_str().unwrap().to_string();
        let snapshot = Snapshot {
            api_version: Some("v1.3".into()),
            nodes: vec![node(&ids, &place, version, "studio-mac", description.clock.as_ref())],
            devices: vec![device(&ids, &place, version, "test")],
            sources: vec![source],
            flows: vec![flow],
            senders: vec![sender],
            receivers: vec![receiver(&ids, version, "in", true, &["en0".into()], false)],
            manifests: [(ids.endpoint.clone(), Manifest::fetched(href, description.sdp(1)))].into(),
            ..Snapshot::default()
        };
        let report = st2110_nmos::check(&snapshot);
        let errors: Vec<_> = report.findings.iter().filter(|f| f.severity == st2110_sdp::Severity::Error).collect();
        assert!(errors.is_empty(), "{errors:#?}");
        let flow_sdp: Vec<_> = report.findings.iter().filter(|f| f.rule.starts_with("flow-")).collect();
        assert!(flow_sdp.is_empty(), "{flow_sdp:#?}");
    }

    #[test]
    fn describes_video_and_audio_as_the_check_reads_them() {
        let mut video = VideoFormat::from_name("1080i50").unwrap();
        video.sampling = Sampling::YCbCr420;
        check(Media::Video(video));
        check(Media::Audio(AudioFormat::new(8)));
        check(Media::Audio(AudioFormat { aes3: true, ..AudioFormat::new(2) }));
    }
}
