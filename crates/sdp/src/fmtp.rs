//! Format parameters from `a=fmtp` lines.

/// One format parameter: `name=value`, or a bare `name` flag such as `interlace`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Param {
    /// The name as written.
    pub name: String,
    /// The value without surrounding quotes; `None` for a flag.
    pub value: Option<String>,
    /// True when the value was written in double quotes.
    pub quoted: bool,
}

/// The parameters of one `a=fmtp` line, in the order written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fmtp {
    /// Parameters in input order, repeats included.
    pub params: Vec<Param>,
}

impl Fmtp {
    /// Splits a parameter list. Returns the parameters and a description of each problem.
    ///
    /// Parameters may be separated by `;` with or without a following space, values
    /// may be quoted, and braces (as in `DID_SDID={0x61,0x01}`) are kept whole.
    pub fn parse(text: &str) -> (Self, Vec<String>) {
        let mut params = Vec::new();
        let mut problems = Vec::new();
        for segment in split(text, &mut problems) {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let (name, value) = match segment.split_once('=') {
                Some((name, value)) => (name.trim(), Some(value.trim())),
                None => (segment, None),
            };
            if name.is_empty() {
                problems.push(format!("`{segment}` has no parameter name"));
                continue;
            }
            if name.contains(char::is_whitespace) {
                problems.push(format!("`{name}` is not a parameter name; is a `;` missing?"));
            }
            let (value, quoted) = match value {
                Some(v) if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') => {
                    (Some(v[1..v.len() - 1].to_string()), true)
                }
                Some(v) => {
                    if v.split_whitespace().skip(1).any(|word| word.contains('=')) {
                        problems.push(format!("the value of {name} runs into another parameter; is a `;` missing?"));
                    }
                    (Some(v.to_string()), false)
                }
                None => (None, false),
            };
            params.push(Param { name: name.to_string(), value, quoted });
        }
        (Self { params }, problems)
    }

    /// The first parameter with this name, compared case-insensitively.
    pub fn get(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// The value of the first parameter with this name.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.get(name)?.value.as_deref()
    }

    /// True if the parameter is present, with or without a value.
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Every parameter with this name.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Param> + 'a {
        self.params.iter().filter(move |p| p.name.eq_ignore_ascii_case(name))
    }
}

/// Splits on `;` outside double quotes and braces.
fn split<'a>(text: &'a str, problems: &mut Vec<String>) -> Vec<&'a str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut depth) = (0, false, 0usize);
    for (i, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '{' if !quoted => depth += 1,
            '}' if !quoted => depth = depth.saturating_sub(1),
            ';' if !quoted && depth == 0 => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if quoted {
        problems.push("a quoted value is never closed".into());
    }
    if depth > 0 {
        problems.push("a `{` is never closed".into());
    }
    out.push(&text[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(fmtp: &Fmtp) -> Vec<&str> {
        fmtp.params.iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn separators_with_and_without_spaces() {
        let (fmtp, problems) = Fmtp::parse("sampling=YCbCr-4:2:2; width=1920;height=1080 ;  depth=10");
        assert!(problems.is_empty());
        assert_eq!(names(&fmtp), ["sampling", "width", "height", "depth"]);
        assert_eq!(fmtp.value("height"), Some("1080"));
    }

    #[test]
    fn flags_quotes_and_case() {
        let (fmtp, problems) = Fmtp::parse("interlace; SSN=\"ST2110-20:2017\"; tp=2110TPN;");
        assert!(problems.is_empty());
        assert_eq!(fmtp.get("interlace").unwrap().value, None);
        let ssn = fmtp.get("SSN").unwrap();
        assert_eq!((ssn.value.as_deref(), ssn.quoted), (Some("ST2110-20:2017"), true));
        assert_eq!(fmtp.value("TP"), Some("2110TPN"));
    }

    #[test]
    fn braces_and_repeats() {
        let (fmtp, problems) = Fmtp::parse("DID_SDID={0x61,0x01};DID_SDID={0x41,0x07};SSN=ST2110-40:2018");
        assert!(problems.is_empty());
        let values: Vec<_> = fmtp.all("DID_SDID").map(|p| p.value.as_deref().unwrap()).collect();
        assert_eq!(values, ["{0x61,0x01}", "{0x41,0x07}"]);
    }

    #[test]
    fn base64_values_are_not_mistaken_for_missing_separators() {
        let (_, problems) = Fmtp::parse("sprop-parameter-sets=Z0IACpZTBYmI,aMljiA==; profile-level-id=42000a");
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn reports_problems() {
        let (_, problems) = Fmtp::parse("width=1920 height=1080");
        assert_eq!(problems.len(), 1, "{problems:?}");
        let (_, problems) = Fmtp::parse("=5; SSN=\"ST2110-20:2017");
        assert_eq!(problems.len(), 2, "{problems:?}");
        let (_, problems) = Fmtp::parse("DID_SDID={0x61,0x01");
        assert_eq!(problems.len(), 1, "{problems:?}");
    }
}
