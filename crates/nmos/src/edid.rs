//! BCP-005-01 v1.0: a Receiver's capabilities from the EDID of the display behind it.
//!
//! [`receiver_caps`] reads an E-EDID, its base block (EDID 1.3 or 1.4) and any CTA-861
//! extension blocks, and maps what it says the display takes into BCP-004-01
//! constraint sets, as BCP-005-01 (EDID to Receiver Caps Mapping) has it:
//!
//! - video: one constraint set per video mode, from the Established Timings I, II and
//!   III, the Standard Timings, the Detailed Timing Descriptors of the base block and
//!   the extensions, the CVT 3 Byte Codes and the Short Video Descriptors, each with
//!   `frame_width`, `frame_height`, `grain_rate` and `interlace_mode`, the colour
//!   sampling the display takes (the base block's Feature Support without an
//!   extension, the CTA-861 header and its YCbCr 4:2:0 data blocks with one), and the
//!   component depth (the base block's Color Bit Depth, and an HDMI Vendor-Specific
//!   Data Block's deep colour flags);
//! - preference: the Preferred Timing Mode highest (`urn:x-nmos:cap:meta:preference`
//!   100), native formats next (50), a CVT code's preferred rate above its others (10);
//! - audio: one constraint set per Linear PCM Short Audio Descriptor, with its media
//!   type from the sample sizes, channel count and sample rates, each an `enum`; and
//!   with Basic Audio and no descriptors, `audio/L8` and 2 channels.
//!
//! Where an EDID gives a rate whose timing runs at 1000/1001 of it, as CTA-861 VICs at
//! a multiple of 6 Hz do, both rates are given (Vertical Frequency Discrepancy). The
//! Established, Standard and CVT timings give the whole rate the mode is named for.
//! What the mapping leaves out is listed in [`ReceiverCaps::notes`]: audio formats
//! other than Linear PCM, the Colorimetry Data Block, and blocks that are not CTA-861.
//!
//! ```
//! use st2110_nmos::edid;
//!
//! // A base block that gives only Established Timing 640x480 at 60 Hz.
//! let mut block = vec![0u8; 128];
//! block[..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
//! block[18] = 1;
//! block[19] = 3;
//! block[35] = 0x20;
//! block[38..54].fill(0x01);
//! let sum = block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
//! block[127] = sum.wrapping_neg();
//! let caps = edid::receiver_caps(&block).unwrap();
//! assert_eq!(caps.video[0]["urn:x-nmos:cap:format:frame_width"]["enum"][0], 640);
//! ```

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

/// The capability URNs this mapping uses.
mod cap {
    pub const WIDTH: &str = "urn:x-nmos:cap:format:frame_width";
    pub const HEIGHT: &str = "urn:x-nmos:cap:format:frame_height";
    pub const RATE: &str = "urn:x-nmos:cap:format:grain_rate";
    pub const INTERLACE: &str = "urn:x-nmos:cap:format:interlace_mode";
    pub const SAMPLING: &str = "urn:x-nmos:cap:format:color_sampling";
    pub const DEPTH: &str = "urn:x-nmos:cap:format:component_depth";
    pub const MEDIA_TYPE: &str = "urn:x-nmos:cap:format:media_type";
    pub const CHANNELS: &str = "urn:x-nmos:cap:format:channel_count";
    pub const SAMPLE_RATE: &str = "urn:x-nmos:cap:format:sample_rate";
    pub const PREFERENCE: &str = "urn:x-nmos:cap:meta:preference";
}

/// The preference of the Preferred Timing Mode, the highest of all.
const PREFERRED: i64 = 100;
/// The preference of a native format.
const NATIVE: i64 = 50;
/// The preference of a CVT 3 Byte Code's preferred vertical rate.
const CVT_PREFERRED: i64 = 10;

const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];

/// What an EDID says a Receiver's Output can take, as BCP-004-01 constraint sets.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReceiverCaps {
    /// A video Receiver's `caps.constraint_sets`.
    pub video: Vec<Value>,
    /// An audio Receiver's `caps.constraint_sets`: empty when the EDID says the display
    /// takes no audio.
    pub audio: Vec<Value>,
    /// What the mapping read and left out, or found wrong, in words.
    pub notes: Vec<String>,
}

impl ReceiverCaps {
    /// As JSON: `video` and `audio`, each `{"constraint_sets": […]}` ready for a
    /// Receiver's `caps`, the audio left out when there is none, and `notes`.
    pub fn to_json(&self) -> Value {
        let mut out = json!({"video": {"constraint_sets": self.video}});
        if !self.audio.is_empty() {
            out["audio"] = json!({"constraint_sets": self.audio});
        }
        out["notes"] = json!(self.notes);
        out
    }
}

/// An EDID from a file's contents: the bytes themselves, or written in hex, as
/// `edid-decode` and `/sys/class/drm/*/edid` dumps are, with any spaces, colons,
/// commas and `0x` between them.
pub fn read(contents: &[u8]) -> Result<Vec<u8>, String> {
    if contents.starts_with(&HEADER) {
        return Ok(contents.to_vec());
    }
    let text = std::str::from_utf8(contents).map_err(|_| "neither an EDID nor hex text".to_string())?;
    let digits: String = text
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, ':' | ',' | '-'))
        .collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("neither an EDID nor hex text".into());
    }
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

/// A video mode the EDID lists.
#[derive(Clone, Debug)]
struct Mode {
    width: u64,
    height: u64,
    /// Frame rates, as fractions.
    rates: Vec<(u64, u64)>,
    interlaced: bool,
    preference: i64,
    /// Colour sampling other than the display's in general: `Some` for a mode a YCbCr
    /// 4:2:0 data block names.
    sampling: Option<Vec<&'static str>>,
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn reduced(numerator: u64, denominator: u64) -> (u64, u64) {
    let g = gcd(numerator, denominator).max(1);
    (numerator / g, denominator / g)
}

fn rational(&(numerator, denominator): &(u64, u64)) -> Value {
    if denominator == 1 {
        json!({"numerator": numerator})
    } else {
        json!({"numerator": numerator, "denominator": denominator})
    }
}

/// A whole rate, with its 1000/1001 flavour too when it is a multiple of 6 Hz, as a
/// CTA-861 VIC's is (BCP-005-01: Vertical Frequency Discrepancy). An interlaced
/// mode's field rate is halved into its frame rate.
fn vic_rates(field_rate: u64, interlaced: bool) -> Vec<(u64, u64)> {
    let divisor = if interlaced { 2 } else { 1 };
    let mut rates = vec![reduced(field_rate, divisor)];
    if field_rate.is_multiple_of(6) {
        rates.push(reduced(field_rate * 1000, 1001 * divisor));
    }
    rates
}

/// The Established Timings I and II (bytes 35 and 36) and the manufacturer's timing
/// (byte 37, bit 7), from bit 7 of each byte to bit 0: width, height, rate and whether
/// interlaced (E-EDID §3.8).
const ESTABLISHED: [(u8, u8, u64, u64, u64, bool); 17] = [
    (0, 7, 720, 400, 70, false),
    (0, 6, 720, 400, 88, false),
    (0, 5, 640, 480, 60, false),
    (0, 4, 640, 480, 67, false),
    (0, 3, 640, 480, 72, false),
    (0, 2, 640, 480, 75, false),
    (0, 1, 800, 600, 56, false),
    (0, 0, 800, 600, 60, false),
    (1, 7, 800, 600, 72, false),
    (1, 6, 800, 600, 75, false),
    (1, 5, 832, 624, 75, false),
    (1, 4, 1024, 768, 87, true),
    (1, 3, 1024, 768, 60, false),
    (1, 2, 1024, 768, 70, false),
    (1, 1, 1024, 768, 75, false),
    (1, 0, 1280, 1024, 75, false),
    (2, 7, 1152, 870, 75, false),
];

/// The Established Timings III (E-EDID §3.10.3.9), from bit 7 of byte 6 of the
/// descriptor onwards: width, height and rate. The reduced-blanking flavours of a mode
/// give the same constraint set as the mode.
const ESTABLISHED_III: [(u64, u64, u64); 44] = [
    (640, 350, 85),
    (640, 400, 85),
    (720, 400, 85),
    (640, 480, 85),
    (848, 480, 60),
    (800, 600, 85),
    (1024, 768, 85),
    (1152, 864, 75),
    (1280, 768, 60),
    (1280, 768, 60),
    (1280, 768, 75),
    (1280, 768, 85),
    (1280, 960, 60),
    (1280, 960, 85),
    (1280, 1024, 60),
    (1280, 1024, 85),
    (1360, 768, 60),
    (1440, 900, 60),
    (1440, 900, 60),
    (1440, 900, 75),
    (1440, 900, 85),
    (1400, 1050, 60),
    (1400, 1050, 60),
    (1400, 1050, 75),
    (1400, 1050, 85),
    (1680, 1050, 60),
    (1680, 1050, 60),
    (1680, 1050, 75),
    (1680, 1050, 85),
    (1600, 1200, 60),
    (1600, 1200, 65),
    (1600, 1200, 70),
    (1600, 1200, 75),
    (1600, 1200, 85),
    (1792, 1344, 60),
    (1792, 1344, 75),
    (1856, 1392, 60),
    (1856, 1392, 75),
    (1920, 1200, 60),
    (1920, 1200, 60),
    (1920, 1200, 75),
    (1920, 1200, 85),
    (1920, 1440, 60),
    (1920, 1440, 75),
];

/// CTA-861 Video Identification Codes (CTA-861 §4.1): VIC, active width (the picture's,
/// for the modes with pixel repetition written `720(1440)`), height of the frame, rate
/// (the field rate for interlaced modes) and whether interlaced.
#[rustfmt::skip]
const VICS: &[(u8, u64, u64, u64, bool)] = &[
    (1, 640, 480, 60, false), (2, 720, 480, 60, false), (3, 720, 480, 60, false), (4, 1280, 720, 60, false),
    (5, 1920, 1080, 60, true), (6, 720, 480, 60, true), (7, 720, 480, 60, true), (8, 720, 240, 60, false),
    (9, 720, 240, 60, false), (10, 2880, 480, 60, true), (11, 2880, 480, 60, true), (12, 2880, 240, 60, false),
    (13, 2880, 240, 60, false), (14, 1440, 480, 60, false), (15, 1440, 480, 60, false), (16, 1920, 1080, 60, false),
    (17, 720, 576, 50, false), (18, 720, 576, 50, false), (19, 1280, 720, 50, false), (20, 1920, 1080, 50, true),
    (21, 720, 576, 50, true), (22, 720, 576, 50, true), (23, 720, 288, 50, false), (24, 720, 288, 50, false),
    (25, 2880, 576, 50, true), (26, 2880, 576, 50, true), (27, 2880, 288, 50, false), (28, 2880, 288, 50, false),
    (29, 1440, 576, 50, false), (30, 1440, 576, 50, false), (31, 1920, 1080, 50, false), (32, 1920, 1080, 24, false),
    (33, 1920, 1080, 25, false), (34, 1920, 1080, 30, false), (35, 2880, 480, 60, false), (36, 2880, 480, 60, false),
    (37, 2880, 576, 50, false), (38, 2880, 576, 50, false), (39, 1920, 1080, 50, true), (40, 1920, 1080, 100, true),
    (41, 1280, 720, 100, false), (42, 720, 576, 100, false), (43, 720, 576, 100, false), (44, 720, 576, 100, true),
    (45, 720, 576, 100, true), (46, 1920, 1080, 120, true), (47, 1280, 720, 120, false), (48, 720, 480, 120, false),
    (49, 720, 480, 120, false), (50, 720, 480, 120, true), (51, 720, 480, 120, true), (52, 720, 576, 200, false),
    (53, 720, 576, 200, false), (54, 720, 576, 200, true), (55, 720, 576, 200, true), (56, 720, 480, 240, false),
    (57, 720, 480, 240, false), (58, 720, 480, 240, true), (59, 720, 480, 240, true), (60, 1280, 720, 24, false),
    (61, 1280, 720, 25, false), (62, 1280, 720, 30, false), (63, 1920, 1080, 120, false),
    (64, 1920, 1080, 100, false), (65, 1280, 720, 24, false), (66, 1280, 720, 25, false), (67, 1280, 720, 30, false),
    (68, 1280, 720, 50, false), (69, 1280, 720, 60, false), (70, 1280, 720, 100, false), (71, 1280, 720, 120, false),
    (72, 1920, 1080, 24, false), (73, 1920, 1080, 25, false), (74, 1920, 1080, 30, false),
    (75, 1920, 1080, 50, false), (76, 1920, 1080, 60, false), (77, 1920, 1080, 100, false),
    (78, 1920, 1080, 120, false), (79, 1680, 720, 24, false), (80, 1680, 720, 25, false), (81, 1680, 720, 30, false),
    (82, 1680, 720, 50, false), (83, 1680, 720, 60, false), (84, 1680, 720, 100, false), (85, 1680, 720, 120, false),
    (86, 2560, 1080, 24, false), (87, 2560, 1080, 25, false), (88, 2560, 1080, 30, false),
    (89, 2560, 1080, 50, false), (90, 2560, 1080, 60, false), (91, 2560, 1080, 100, false),
    (92, 2560, 1080, 120, false), (93, 3840, 2160, 24, false), (94, 3840, 2160, 25, false),
    (95, 3840, 2160, 30, false), (96, 3840, 2160, 50, false), (97, 3840, 2160, 60, false),
    (98, 4096, 2160, 24, false), (99, 4096, 2160, 25, false), (100, 4096, 2160, 30, false),
    (101, 4096, 2160, 50, false), (102, 4096, 2160, 60, false), (103, 3840, 2160, 24, false),
    (104, 3840, 2160, 25, false), (105, 3840, 2160, 30, false), (106, 3840, 2160, 50, false),
    (107, 3840, 2160, 60, false), (108, 1280, 720, 48, false), (109, 1280, 720, 48, false),
    (110, 1680, 720, 48, false), (111, 1920, 1080, 48, false), (112, 1920, 1080, 48, false),
    (113, 2560, 1080, 48, false), (114, 3840, 2160, 48, false), (115, 4096, 2160, 48, false),
    (116, 3840, 2160, 48, false), (117, 3840, 2160, 100, false), (118, 3840, 2160, 120, false),
    (119, 3840, 2160, 100, false), (120, 3840, 2160, 120, false), (121, 5120, 2160, 24, false),
    (122, 5120, 2160, 25, false), (123, 5120, 2160, 30, false), (124, 5120, 2160, 48, false),
    (125, 5120, 2160, 50, false), (126, 5120, 2160, 60, false), (127, 5120, 2160, 100, false),
    (193, 5120, 2160, 120, false), (194, 7680, 4320, 24, false), (195, 7680, 4320, 25, false),
    (196, 7680, 4320, 30, false), (197, 7680, 4320, 48, false), (198, 7680, 4320, 50, false),
    (199, 7680, 4320, 60, false), (200, 7680, 4320, 100, false), (201, 7680, 4320, 120, false),
    (202, 7680, 4320, 24, false), (203, 7680, 4320, 25, false), (204, 7680, 4320, 30, false),
    (205, 7680, 4320, 48, false), (206, 7680, 4320, 50, false), (207, 7680, 4320, 60, false),
    (208, 7680, 4320, 100, false), (209, 7680, 4320, 120, false), (210, 10240, 4320, 24, false),
    (211, 10240, 4320, 25, false), (212, 10240, 4320, 30, false), (213, 10240, 4320, 48, false),
    (214, 10240, 4320, 50, false), (215, 10240, 4320, 60, false), (216, 10240, 4320, 100, false),
    (217, 10240, 4320, 120, false), (218, 4096, 2160, 100, false), (219, 4096, 2160, 120, false),
];

/// The VIC a Short Video Descriptor names, and whether it marks a native format
/// (CTA-861 §7.5.1): 129 to 192 are VICs 1 to 64, native.
fn svd(byte: u8) -> (u8, bool) {
    if (129..=192).contains(&byte) { (byte - 128, true) } else { (byte, false) }
}

fn vic_mode(vic: u8, preference: i64) -> Option<Mode> {
    let &(_, width, height, rate, interlaced) = VICS.iter().find(|v| v.0 == vic)?;
    Some(Mode { width, height, rates: vic_rates(rate, interlaced), interlaced, preference, sampling: None })
}

fn whole(width: u64, height: u64, rate: u64, interlaced: bool) -> Mode {
    let rate = if interlaced { reduced(rate, 2) } else { (rate, 1) };
    Mode { width, height, rates: vec![rate], interlaced, preference: 0, sampling: None }
}

/// A Standard Timing (E-EDID §3.9), or `None` for an unused one.
fn standard_timing(bytes: [u8; 2], revision: u8) -> Option<Mode> {
    if bytes == [0x01, 0x01] || bytes[0] == 0 {
        return None;
    }
    let width = (u64::from(bytes[0]) + 31) * 8;
    let height = match bytes[1] >> 6 {
        // 16:10 from EDID 1.3; 1:1 before it.
        0 if revision < 3 => width,
        0 => width * 10 / 16,
        1 => width * 3 / 4,
        2 => width * 4 / 5,
        _ => width * 9 / 16,
    };
    Some(whole(width, height, u64::from(bytes[1] & 0x3f) + 60, false))
}

/// A Detailed Timing Descriptor (E-EDID §3.10.2), or `None` when it is not one.
fn detailed_timing(d: &[u8]) -> Option<Mode> {
    let clock = u64::from(u16::from_le_bytes([d[0], d[1]])) * 10_000;
    if clock == 0 {
        return None;
    }
    let width = u64::from(d[2]) | (u64::from(d[4] >> 4) << 8);
    let h_blank = u64::from(d[3]) | (u64::from(d[4] & 0x0f) << 8);
    let lines = u64::from(d[5]) | (u64::from(d[7] >> 4) << 8);
    let v_blank = u64::from(d[6]) | (u64::from(d[7] & 0x0f) << 8);
    let interlaced = d[17] & 0x80 != 0;
    // An interlaced timing gives a field's lines; its frame has two fields and the half
    // line between them.
    let (height, total_lines) =
        if interlaced { (lines * 2, (lines + v_blank) * 2 + 1) } else { (lines, lines + v_blank) };
    let total = (width + h_blank) * total_lines;
    if width == 0 || height == 0 || total == 0 {
        return None;
    }
    Some(Mode { width, height, rates: vec![reduced(clock, total)], interlaced, preference: 0, sampling: None })
}

/// The modes of a CVT 3 Byte Code descriptor (E-EDID §3.10.3.8).
fn cvt_codes(d: &[u8], modes: &mut Vec<Mode>) {
    for code in d[6..18].chunks(3) {
        if code == [0, 0, 0] {
            continue;
        }
        let height = ((u64::from(code[0]) | (u64::from(code[1] >> 4) << 8)) + 1) * 2;
        let width = match (code[1] >> 2) & 0x03 {
            0 => height * 4 / 3,
            1 => height * 16 / 9,
            2 => height * 16 / 10,
            _ => height * 15 / 9,
        } & !7;
        let preferred = match (code[2] >> 5) & 0x03 {
            0 => 50,
            1 => 60,
            2 => 75,
            _ => 85,
        };
        let supported = [(0x10, 50), (0x08, 60), (0x04, 75), (0x02, 85), (0x01, 60)];
        let mut seen = BTreeSet::new();
        for (bit, rate) in supported {
            if code[2] & bit != 0 && seen.insert(rate) {
                let mut mode = whole(width, height, rate, false);
                mode.preference = if rate == preferred { CVT_PREFERRED } else { 0 };
                modes.push(mode);
            }
        }
    }
}

/// The base block's 18-byte descriptors.
fn descriptors(block: &[u8], revision: u8, modes: &mut Vec<Mode>, dtds: &mut Vec<Mode>, notes: &mut Vec<String>) {
    for d in block[54..126].chunks(18) {
        if let Some(mode) = detailed_timing(d) {
            dtds.push(mode);
            continue;
        }
        match d[3] {
            0xf7 => {
                for (i, &(w, h, r)) in ESTABLISHED_III.iter().enumerate() {
                    if d[6 + i / 8] & (0x80 >> (i % 8)) != 0 {
                        modes.push(whole(w, h, r, false));
                    }
                }
            }
            0xf8 => cvt_codes(d, modes),
            0xfa => modes.extend(d[5..17].chunks(2).filter_map(|st| standard_timing([st[0], st[1]], revision))),
            0xfd | 0xfc | 0xff | 0xfe | 0xfb | 0xf9 | 0x10 => {}
            tag => notes.push(format!("display descriptor 0x{tag:02x} in the base block is not read")),
        }
    }
}

/// What the CTA-861 extensions say, beyond their modes.
#[derive(Default)]
struct Cta {
    /// The YCbCr samplings the header says every mode takes.
    ycbcr444: bool,
    ycbcr422: bool,
    basic_audio: bool,
    /// The number of native Detailed Timing Descriptors, counted from the first.
    native_dtds: usize,
    /// The VICs of the Short Video Descriptors, in order, and whether each is native.
    svds: Vec<(u8, bool)>,
    /// The SVDs a YCbCr 4:2:0 Capability Map marks, by their place in `svds`; `None` in
    /// the list for a map that names them all.
    map_420: Vec<Option<usize>>,
    /// The VICs of YCbCr 4:2:0 Video Data Blocks: 4:2:0 only.
    only_420: Vec<u8>,
    /// Linear PCM Short Audio Descriptors.
    sads: Vec<[u8; 3]>,
    /// Component depths an HDMI Vendor-Specific Data Block adds.
    depths: BTreeSet<u64>,
    dtds: Vec<Mode>,
}

/// Reads a CTA-861 extension block (CTA-861 §7.5), adding to `cta`.
fn cta_block(block: &[u8], number: usize, cta: &mut Cta, notes: &mut Vec<String>) {
    let offset = usize::from(block[2]);
    let flags = block[3];
    cta.ycbcr444 |= flags & 0x20 != 0;
    cta.ycbcr422 |= flags & 0x10 != 0;
    cta.basic_audio |= flags & 0x40 != 0;
    cta.native_dtds = cta.native_dtds.max(usize::from(flags & 0x0f));
    if offset == 0 {
        return;
    }
    if !(4..=127).contains(&offset) {
        notes.push(format!("extension block {number} gives its timings at byte {offset}, outside the block"));
        return;
    }
    let mut at = 4;
    while at < offset {
        let header = block[at];
        let length = usize::from(header & 0x1f);
        let Some(payload) = block.get(at + 1..at + 1 + length).filter(|_| at + 1 + length <= offset) else {
            notes.push(format!("extension block {number}: a data block runs past the data block collection"));
            break;
        };
        match header >> 5 {
            1 => {
                for sad in payload.as_chunks::<3>().0 {
                    match (sad[0] >> 3) & 0x0f {
                        1 => cta.sads.push([sad[0], sad[1], sad[2]]),
                        code => notes.push(format!(
                            "a Short Audio Descriptor with Audio Format Code {code} (not Linear PCM) has no constraint set here"
                        )),
                    }
                }
            }
            2 => cta.svds.extend(payload.iter().filter(|b| !matches!(b, 0 | 128 | 254 | 255)).map(|b| svd(*b))),
            3 if payload.len() >= 6 && payload[..3] == [0x03, 0x0c, 0x00] => {
                // HDMI 1.4 VSDB: 8 bits per component always, and the deep colour flags.
                cta.depths.insert(8);
                for (bit, depth) in [(0x10, 10), (0x20, 12), (0x40, 16)] {
                    if payload[5] & bit != 0 {
                        cta.depths.insert(depth);
                    }
                }
            }
            7 => match payload.first() {
                Some(14) => cta.only_420.extend(payload[1..].iter().map(|b| svd(*b).0)),
                Some(15) if payload.len() == 1 => cta.map_420.push(None),
                Some(15) => {
                    for (byte, bits) in payload[1..].iter().enumerate() {
                        cta.map_420.extend((0..8).filter(|bit| bits & (1 << bit) != 0).map(|bit| Some(byte * 8 + bit)));
                    }
                }
                Some(5) => notes.push("the Colorimetry Data Block is not mapped to colorspace here".into()),
                _ => {}
            },
            _ => {}
        }
        at += 1 + length;
    }
    let mut at = offset;
    while at + 18 <= 127 {
        match detailed_timing(&block[at..at + 18]) {
            Some(mode) => cta.dtds.push(mode),
            None => break,
        }
        at += 18;
    }
}

/// The Receiver capabilities an EDID gives, as BCP-005-01 maps them. Fails when the
/// bytes are not an E-EDID.
pub fn receiver_caps(edid: &[u8]) -> Result<ReceiverCaps, String> {
    if edid.len() < 128 || !edid.len().is_multiple_of(128) {
        return Err(format!("{} bytes: an EDID is one or more blocks of 128", edid.len()));
    }
    let base = &edid[..128];
    if base[..8] != HEADER {
        return Err("no EDID header (00 ff ff ff ff ff ff 00) at the start".into());
    }
    let mut notes = Vec::new();
    for (n, block) in edid.chunks(128).enumerate() {
        if block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
            notes.push(format!("block {n}'s checksum is wrong; it is read as it is"));
        }
    }
    let (version, revision) = (base[18], base[19]);
    if version != 1 {
        return Err(format!("EDID version {version}.{revision}: this reads version 1 (E-EDID 1.3 and 1.4)"));
    }
    let digital = base[20] & 0x80 != 0;

    let mut modes = Vec::new();
    for &(byte, bit, w, h, r, interlaced) in &ESTABLISHED {
        if base[35 + usize::from(byte)] & (1 << bit) != 0 {
            modes.push(whole(w, h, r, interlaced));
        }
    }
    modes.extend(base[38..54].chunks(2).filter_map(|st| standard_timing([st[0], st[1]], revision)));
    let mut dtds = Vec::new();
    descriptors(base, revision, &mut modes, &mut dtds, &mut notes);

    let mut cta = Cta::default();
    let mut extensions = 0;
    for (n, block) in edid.chunks(128).enumerate().skip(1) {
        if block[0] == 0x02 {
            extensions += 1;
            cta_block(block, n, &mut cta, &mut notes);
        } else {
            notes.push(format!("extension block {n} (tag 0x{:02x}) is not CTA-861 and is not read", block[0]));
        }
    }
    if usize::from(base[126]) != edid.len() / 128 - 1 {
        notes.push(format!(
            "the base block says {} extension blocks follow, and {} do",
            base[126],
            edid.len() / 128 - 1
        ));
    }

    // Preference: the first DTD of the base block is the Preferred Timing Mode; the
    // first DTDs, as many as the CTA header says, and the SVDs marked so are native.
    let has_preferred = !dtds.is_empty();
    dtds.extend(std::mem::take(&mut cta.dtds));
    for (i, mode) in dtds.iter_mut().enumerate() {
        mode.preference = if i == 0 && has_preferred {
            PREFERRED
        } else if i < cta.native_dtds {
            NATIVE
        } else {
            0
        };
    }
    let mut ordered: Vec<Mode> = dtds;
    for (i, &(vic, native)) in cta.svds.iter().enumerate() {
        let preference = if i == 0 && !has_preferred {
            PREFERRED
        } else if native {
            NATIVE
        } else {
            0
        };
        let Some(mut mode) = vic_mode(vic, preference) else {
            notes.push(format!("VIC {vic} is not one this mapping knows"));
            continue;
        };
        if cta.map_420.iter().any(|m| m.is_none_or(|place| place == i)) {
            mode.sampling = Some(vec!["YCbCr-4:2:0"]);
        }
        ordered.push(mode);
    }
    for &vic in &cta.only_420 {
        match vic_mode(vic, 0) {
            Some(mut mode) => {
                mode.sampling = Some(Vec::new());
                ordered.push(mode);
            }
            None => notes.push(format!("VIC {vic} is not one this mapping knows")),
        }
    }
    ordered.extend(modes);

    // Colour sampling: from the extensions when there are any, otherwise the base
    // block's Feature Support (EDID 1.4, digital).
    let mut sampling = vec!["RGB"];
    if extensions > 0 {
        if cta.ycbcr444 {
            sampling.push("YCbCr-4:4:4");
        }
        if cta.ycbcr422 {
            sampling.push("YCbCr-4:2:2");
        }
    } else if digital && revision >= 4 {
        let encodings = (base[24] >> 3) & 0x03;
        if encodings & 0x01 != 0 {
            sampling.push("YCbCr-4:4:4");
        }
        if encodings & 0x02 != 0 {
            sampling.push("YCbCr-4:2:2");
        }
    }
    // Component depth: the base block's Color Bit Depth (EDID 1.4, digital), with what
    // an HDMI VSDB adds.
    let mut depths = cta.depths.clone();
    if digital
        && revision >= 4
        && let depth @ 1..=6 = (base[20] >> 4) & 0x07
    {
        depths.insert(4 + 2 * u64::from(depth));
    }

    let mut video: Vec<Value> = Vec::new();
    let mut keys: Vec<Value> = Vec::new();
    for mode in ordered {
        let mut set = Map::new();
        set.insert(cap::WIDTH.into(), json!({"enum": [mode.width]}));
        set.insert(cap::HEIGHT.into(), json!({"enum": [mode.height]}));
        set.insert(cap::RATE.into(), json!({"enum": mode.rates.iter().map(rational).collect::<Vec<_>>()}));
        let interlace =
            if mode.interlaced { json!(["interlaced_tff", "interlaced_bff"]) } else { json!(["progressive"]) };
        set.insert(cap::INTERLACE.into(), json!({"enum": interlace}));
        let mut samplings = sampling.clone();
        match &mode.sampling {
            Some(only) if only.is_empty() => samplings = vec!["YCbCr-4:2:0"],
            Some(more) => samplings.extend(more.iter().copied()),
            None => {}
        }
        set.insert(cap::SAMPLING.into(), json!({"enum": samplings}));
        if !depths.is_empty() {
            set.insert(cap::DEPTH.into(), json!({"enum": depths}));
        }
        // The same mode twice is one constraint set, at the higher preference.
        let key = Value::Object(set.clone());
        match keys.iter().position(|k| *k == key) {
            Some(i) => {
                let had = video[i].get(cap::PREFERENCE).and_then(Value::as_i64).unwrap_or(0);
                if mode.preference > had {
                    video[i][cap::PREFERENCE] = json!(mode.preference);
                }
            }
            None => {
                if mode.preference != 0 {
                    set.insert(cap::PREFERENCE.into(), json!(mode.preference));
                }
                keys.push(key);
                video.push(Value::Object(set));
            }
        }
    }

    let mut audio = Vec::new();
    for sad in &cta.sads {
        let mut types = Vec::new();
        for (bit, media_type) in [(0x01, "audio/L16"), (0x02, "audio/L20"), (0x04, "audio/L24")] {
            if sad[2] & bit != 0 {
                types.push(media_type);
            }
        }
        let rates: Vec<Value> = [32_000, 44_100, 48_000, 88_200, 96_000, 176_400, 192_000]
            .iter()
            .enumerate()
            .filter(|(bit, _)| sad[1] & (1 << bit) != 0)
            .map(|(_, rate)| json!({"numerator": rate}))
            .collect();
        if types.is_empty() || rates.is_empty() {
            notes.push("a Linear PCM Short Audio Descriptor gives no sample size or no sample rate".into());
            continue;
        }
        audio.push(json!({
            cap::MEDIA_TYPE: {"enum": types},
            cap::CHANNELS: {"enum": [u64::from(sad[0] & 0x07) + 1]},
            cap::SAMPLE_RATE: {"enum": rates},
        }));
    }
    if audio.is_empty() && cta.basic_audio {
        audio.push(json!({cap::MEDIA_TYPE: {"enum": ["audio/L8"]}, cap::CHANNELS: {"enum": [2]}}));
    }
    Ok(ReceiverCaps { video, audio, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(block: &mut [u8]) {
        block[127] = 0;
        let sum = block.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        block[127] = sum.wrapping_neg();
    }

    /// A base block of EDID 1.4, digital at `depth` bits, with these Established Timing
    /// bytes, Standard Timings and descriptors, and `extensions` blocks after it.
    fn base(established: [u8; 3], standard: &[[u8; 2]], descriptors: &[[u8; 18]], extensions: u8) -> Vec<u8> {
        let mut block = vec![0u8; 128];
        block[..8].copy_from_slice(&HEADER);
        block[18] = 1;
        block[19] = 4;
        // Digital, 10 bits per primary colour, HDMI-a.
        block[20] = 0x80 | (3 << 4) | 0x02;
        // RGB 4:4:4 & YCrCb 4:2:2.
        block[24] = 0x02 << 3;
        block[35..38].copy_from_slice(&established);
        block[38..54].fill(0x01);
        for (i, st) in standard.iter().enumerate() {
            block[38 + 2 * i..40 + 2 * i].copy_from_slice(st);
        }
        for (i, d) in descriptors.iter().enumerate() {
            block[54 + 18 * i..72 + 18 * i].copy_from_slice(d);
        }
        // Unused descriptors are dummies (tag 0x10).
        for i in descriptors.len()..4 {
            block[54 + 18 * i + 3] = 0x10;
        }
        block[126] = extensions;
        checksum(&mut block);
        block
    }

    /// A Detailed Timing Descriptor.
    fn dtd(clock_10khz: u16, h: u16, h_blank: u16, v: u16, v_blank: u16, interlaced: bool) -> [u8; 18] {
        let mut d = [0u8; 18];
        d[..2].copy_from_slice(&clock_10khz.to_le_bytes());
        d[2] = h as u8;
        d[3] = h_blank as u8;
        d[4] = (((h >> 8) as u8) << 4) | (h_blank >> 8) as u8;
        d[5] = v as u8;
        d[6] = v_blank as u8;
        d[7] = (((v >> 8) as u8) << 4) | (v_blank >> 8) as u8;
        d[17] = if interlaced { 0x80 | 0x18 } else { 0x18 };
        d
    }

    fn enumerated(set: &Value, cap: &str) -> Vec<Value> {
        set[cap]["enum"].as_array().cloned().unwrap_or_default()
    }

    fn mode(set: &Value) -> (u64, u64, Vec<Value>, String) {
        (
            set[cap::WIDTH]["enum"][0].as_u64().unwrap(),
            set[cap::HEIGHT]["enum"][0].as_u64().unwrap(),
            enumerated(set, cap::RATE),
            set[cap::INTERLACE]["enum"][0].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn maps_the_examples_of_bcp_005_01() {
        // Examples: Established Timings `20 08 00`.
        let caps = receiver_caps(&base([0x20, 0x08, 0x00], &[], &[], 0)).unwrap();
        let modes: Vec<_> = caps.video.iter().map(mode).collect();
        assert_eq!(
            modes,
            [
                (640, 480, vec![json!({"numerator": 60})], "progressive".into()),
                (1024, 768, vec![json!({"numerator": 60})], "progressive".into()),
            ]
        );
        // Examples: Standard Timings `D1 C0`. The example gives the width as 1080 and
        // the height as 1920; the mapping's text, followed here, takes the width from
        // the Horizontal Active Pixel Count, (0xD1 + 31) × 8 = 1920, and the height
        // from it and the 16:9 aspect ratio.
        let caps = receiver_caps(&base([0; 3], &[[0xd1, 0xc0]], &[], 0)).unwrap();
        assert_eq!(mode(&caps.video[0]), (1920, 1080, vec![json!({"numerator": 60})], "progressive".into()));
        // Without an extension, sampling from Feature Support and depth from the Video
        // Input Definition go into every set.
        assert_eq!(enumerated(&caps.video[0], cap::SAMPLING), [json!("RGB"), json!("YCbCr-4:2:2")]);
        assert_eq!(enumerated(&caps.video[0], cap::DEPTH), [json!(10)]);
        assert!(caps.audio.is_empty());
        assert!(caps.notes.is_empty(), "{:?}", caps.notes);
    }

    #[test]
    fn reads_detailed_timings_with_the_preferred_one_first() {
        let p60 = dtd(14850, 1920, 280, 1080, 45, false);
        let i50 = dtd(7425, 1920, 720, 540, 22, true);
        let p5994 = dtd(14835, 1920, 280, 1080, 45, false);
        let edid = base([0x20, 0, 0], &[], &[p60, i50, p5994], 0);
        let caps = receiver_caps(&edid).unwrap();
        assert_eq!(mode(&caps.video[0]), (1920, 1080, vec![json!({"numerator": 60})], "progressive".into()));
        assert_eq!(caps.video[0][cap::PREFERENCE], 100);
        // Interlaced: two fields of 540 lines, 25 frames a second.
        assert_eq!(mode(&caps.video[1]), (1920, 1080, vec![json!({"numerator": 25})], "interlaced_tff".into()));
        assert_eq!(enumerated(&caps.video[1], cap::INTERLACE).len(), 2);
        assert!(caps.video[1].get(cap::PREFERENCE).is_none());
        // The pixel clock in 10 kHz steps: 148.35 MHz over 2200 × 1125.
        assert_eq!(enumerated(&caps.video[2], cap::RATE), [json!({"numerator": 1978, "denominator": 33})]);
        assert_eq!(mode(&caps.video[3]).0, 640, "the established timing after the detailed ones");
    }

    /// A CTA-861 extension block with these data blocks and Detailed Timing Descriptors.
    fn cta(flags: u8, data: &[&[u8]], dtds: &[[u8; 18]]) -> Vec<u8> {
        let mut block = vec![0u8; 128];
        block[0] = 0x02;
        block[1] = 3;
        block[3] = flags;
        let mut at = 4;
        for b in data {
            block[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        }
        block[2] = at as u8;
        for d in dtds {
            block[at..at + 18].copy_from_slice(d);
            at += 18;
        }
        checksum(&mut block);
        block
    }

    #[test]
    fn reads_the_cta_861_extension() {
        let p60 = dtd(14850, 1920, 280, 1080, 45, false);
        let mut edid = base([0, 0, 0], &[], &[p60], 1);
        // Basic audio, YCbCr 4:4:4 and 4:2:2, one native DTD.
        let video: &[u8] = &[0x40 | 4, 0x80 | 16, 4, 97, 20];
        // LPCM, 8 channels, 48 and 96 kHz, 16 and 24 bits; then AC-3.
        let audio: &[u8] = &[0x20 | 6, (1 << 3) | 7, 0x04 | 0x10, 0x05, (2 << 3) | 5, 0x07, 0x50];
        // HDMI VSDB: 30 and 36 bits per pixel.
        let hdmi: &[u8] = &[0x60 | 6, 0x03, 0x0c, 0x00, 0x10, 0x00, 0x30];
        // YCbCr 4:2:0 Capability Map: the third SVD (VIC 97); 4:2:0 Video Data Block: VIC 96.
        let map: &[u8] = &[0xe0 | 2, 15, 0x04];
        let only: &[u8] = &[0xe0 | 2, 14, 96];
        let colorimetry: &[u8] = &[0xe0 | 3, 5, 0xc0, 0x00];
        let i60 = dtd(7425, 1920, 280, 540, 22, true);
        edid.extend(cta(0x40 | 0x20 | 0x10 | 1, &[video, audio, hdmi, map, only, colorimetry], &[i60]));
        let caps = receiver_caps(&edid).unwrap();
        let find = |w: u64, h: u64, interlace: &str, rate: Value| {
            caps.video
                .iter()
                .find(|s| {
                    let m = mode(s);
                    (m.0, m.1, m.3.as_str()) == (w, h, interlace) && m.2.contains(&rate)
                })
                .unwrap_or_else(|| panic!("{w}x{h} {interlace} {rate}: {:#?}", caps.video))
        };
        let preferred = find(1920, 1080, "progressive", json!({"numerator": 60}));
        assert_eq!(preferred[cap::PREFERENCE], 100);
        let samplings = |set: &Value| enumerated(set, cap::SAMPLING);
        assert_eq!(samplings(preferred), [json!("RGB"), json!("YCbCr-4:4:4"), json!("YCbCr-4:2:2")]);
        assert_eq!(enumerated(preferred, cap::DEPTH), [json!(8), json!(10), json!(12)]);
        // The DTD of the extension is not native: only the first one is.
        let field = find(1920, 1080, "interlaced_tff", json!({"numerator": 30}));
        assert!(field.get(cap::PREFERENCE).is_none());
        // VIC 16, native, at 60 and 59.94 Hz.
        let vic16 = find(1920, 1080, "progressive", json!({"numerator": 60000, "denominator": 1001}));
        assert_eq!(vic16[cap::PREFERENCE], 50);
        assert_eq!(enumerated(vic16, cap::RATE).len(), 2);
        // VIC 20: 1080i50, 25 frames a second.
        assert_eq!(enumerated(find(1920, 1080, "interlaced_tff", json!({"numerator": 25})), cap::RATE).len(), 1);
        let uhd60 = find(3840, 2160, "progressive", json!({"numerator": 60}));
        assert_eq!(samplings(uhd60).last(), Some(&json!("YCbCr-4:2:0")));
        let uhd50 = find(3840, 2160, "progressive", json!({"numerator": 50}));
        assert_eq!(samplings(uhd50), [json!("YCbCr-4:2:0")]);
        assert!(samplings(find(1280, 720, "progressive", json!({"numerator": 60}))).len() == 3);

        assert_eq!(caps.audio.len(), 1, "{:#?}", caps.audio);
        assert_eq!(caps.audio[0][cap::MEDIA_TYPE]["enum"], json!(["audio/L16", "audio/L24"]));
        assert_eq!(caps.audio[0][cap::CHANNELS]["enum"], json!([8]));
        assert_eq!(caps.audio[0][cap::SAMPLE_RATE]["enum"], json!([{"numerator": 48000}, {"numerator": 96000}]));
        assert!(caps.notes.iter().any(|n| n.contains("Audio Format Code 2")), "{:?}", caps.notes);
        assert!(caps.notes.iter().any(|n| n.contains("Colorimetry")), "{:?}", caps.notes);
        assert_eq!(caps.to_json()["audio"]["constraint_sets"], json!(caps.audio));
    }

    #[test]
    fn basic_audio_alone_is_two_channels() {
        let mut edid = base([0x20, 0, 0], &[], &[], 1);
        edid.extend(cta(0x40, &[], &[]));
        let caps = receiver_caps(&edid).unwrap();
        assert_eq!(caps.audio, [json!({cap::MEDIA_TYPE: {"enum": ["audio/L8"]}, cap::CHANNELS: {"enum": [2]}})]);
        // With an extension, sampling comes from its header: RGB alone here.
        assert_eq!(enumerated(&caps.video[0], cap::SAMPLING), [json!("RGB")]);
    }

    #[test]
    fn reads_display_descriptors() {
        // Established Timings III: 1280x1024 at 60 Hz (byte 7, bit 1).
        let mut et3 = [0u8; 18];
        et3[3] = 0xf7;
        et3[5] = 0x0a;
        et3[7] = 0x02;
        // CVT: 1080 lines, 16:9, 50 and 60 Hz supported, 60 Hz preferred.
        let mut cvt = [0u8; 18];
        cvt[3] = 0xf8;
        cvt[5] = 0x01;
        let code = 1080 / 2 - 1;
        cvt[6] = (code & 0xff) as u8;
        cvt[7] = (((code >> 8) as u8) << 4) | (1 << 2);
        cvt[8] = (1 << 5) | 0x10 | 0x08;
        let caps = receiver_caps(&base([0; 3], &[], &[et3, cvt], 0)).unwrap();
        let modes: Vec<_> = caps.video.iter().map(mode).collect();
        assert_eq!(modes[0].0, 1280);
        assert_eq!(modes[0].1, 1024);
        assert_eq!((modes[1].0, modes[1].1), (1920, 1080));
        assert_eq!(caps.video[1].get(cap::PREFERENCE), None, "50 Hz is supported, not preferred");
        assert_eq!(caps.video[2][cap::PREFERENCE], 10);
        assert_eq!(modes[2].2, [json!({"numerator": 60})]);
    }

    #[test]
    fn refuses_what_is_not_an_edid_and_reads_hex() {
        assert!(receiver_caps(&[0; 100]).is_err());
        assert!(receiver_caps(&[0; 128]).unwrap_err().contains("header"));
        let mut edid = base([0x20, 0, 0], &[], &[], 0);
        edid[40] ^= 1;
        let caps = receiver_caps(&edid).unwrap();
        assert!(caps.notes[0].contains("checksum"), "{:?}", caps.notes);
        let hex: String = base([0x20, 0, 0], &[], &[], 0).iter().map(|b| format!("{b:02x} ")).collect();
        assert_eq!(read(hex.as_bytes()).unwrap(), base([0x20, 0, 0], &[], &[], 0));
        assert_eq!(read(&edid).unwrap(), edid);
        assert!(read(b"hello").is_err());
    }
}
