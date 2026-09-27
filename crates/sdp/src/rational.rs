//! Exact rational numbers, used for frame rates.

use std::fmt;

/// A positive rational number in lowest terms, such as the frame rate `30000/1001`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rational {
    num: u64,
    den: u64,
}

impl Rational {
    /// Builds `num/den` in lowest terms. Returns `None` if either part is zero.
    pub fn new(num: u64, den: u64) -> Option<Self> {
        if num == 0 || den == 0 {
            return None;
        }
        let g = gcd(num, den);
        Some(Self { num: num / g, den: den / g })
    }

    /// The numerator.
    pub fn numerator(self) -> u64 {
        self.num
    }

    /// The denominator.
    pub fn denominator(self) -> u64 {
        self.den
    }

    /// True for whole numbers.
    pub fn is_integer(self) -> bool {
        self.den == 1
    }

    /// The value as a float, for display and tolerances.
    pub fn to_f64(self) -> f64 {
        self.num as f64 / self.den as f64
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

impl fmt::Display for Rational {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.den == 1 { write!(f, "{}", self.num) } else { write!(f, "{}/{}", self.num, self.den) }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Rational {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// How a frame rate was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notation {
    /// `50` or `60000/1001`: the form ST 2110-20 asks for.
    Canonical,
    /// A ratio not in lowest terms, or a whole number written as a ratio (`50/1`).
    NotCanonical,
}

/// Why a frame rate could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRateError {
    /// A decimal such as `59.94`, with the value it most likely stands for.
    Decimal(Option<Rational>),
    /// Not a frame rate at all.
    Invalid,
}

/// Reads an `exactframerate` value: a whole number, or a ratio such as `30000/1001`.
pub fn parse_frame_rate(text: &str) -> Result<(Rational, Notation), FrameRateError> {
    let text = text.trim();
    if let Some((num, den)) = text.split_once('/') {
        let num = digits(num).ok_or(FrameRateError::Invalid)?;
        let den = digits(den).ok_or(FrameRateError::Invalid)?;
        let rate = Rational::new(num, den).ok_or(FrameRateError::Invalid)?;
        let canonical = den != 1 && rate.numerator() == num;
        let notation = if canonical { Notation::Canonical } else { Notation::NotCanonical };
        return Ok((rate, notation));
    }
    if let Some(n) = digits(text) {
        return Rational::new(n, 1).map(|rate| (rate, Notation::Canonical)).ok_or(FrameRateError::Invalid);
    }
    match text.parse::<f64>() {
        Ok(x) if x.is_finite() && x > 0.0 && text.bytes().all(|b| b.is_ascii_digit() || b == b'.') => {
            Err(FrameRateError::Decimal(likely_ratio(x)))
        }
        _ => Err(FrameRateError::Invalid),
    }
}

/// Parses a non-empty run of ASCII digits.
pub(crate) fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The exact rate a decimal most likely stands for: `59.94` is `60000/1001`, `50.0` is `50`.
fn likely_ratio(x: f64) -> Option<Rational> {
    if x.fract() == 0.0 {
        return Rational::new(x as u64, 1);
    }
    let nominal = (x * 1.001).round();
    if nominal >= 1.0 && (x - nominal / 1.001).abs() < 0.01 {
        return Rational::new(nominal as u64 * 1000, 1001);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(num: u64, den: u64) -> Rational {
        Rational::new(num, den).unwrap()
    }

    #[test]
    fn reduces_and_displays() {
        assert_eq!(rate(60000, 2002), rate(30000, 1001));
        assert_eq!(rate(50, 1).to_string(), "50");
        assert_eq!(rate(60000, 1001).to_string(), "60000/1001");
        assert!(Rational::new(0, 1).is_none());
        assert!(Rational::new(1, 0).is_none());
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(parse_frame_rate("50"), Ok((rate(50, 1), Notation::Canonical)));
        assert_eq!(parse_frame_rate("60000/1001"), Ok((rate(60000, 1001), Notation::Canonical)));
    }

    #[test]
    fn non_canonical_forms() {
        assert_eq!(parse_frame_rate("50/1"), Ok((rate(50, 1), Notation::NotCanonical)));
        assert_eq!(parse_frame_rate("120000/2002"), Ok((rate(60000, 1001), Notation::NotCanonical)));
    }

    #[test]
    fn decimals_suggest_the_exact_rate() {
        assert_eq!(parse_frame_rate("59.94"), Err(FrameRateError::Decimal(Some(rate(60000, 1001)))));
        assert_eq!(parse_frame_rate("29.97"), Err(FrameRateError::Decimal(Some(rate(30000, 1001)))));
        assert_eq!(parse_frame_rate("23.976"), Err(FrameRateError::Decimal(Some(rate(24000, 1001)))));
        assert_eq!(parse_frame_rate("50.0"), Err(FrameRateError::Decimal(Some(rate(50, 1)))));
        assert_eq!(parse_frame_rate("12.5"), Err(FrameRateError::Decimal(None)));
    }

    #[test]
    fn rejects_junk() {
        for text in ["", "fast", "0", "0/1", "1/0", "-50", "+50", "5e1", "30000/"] {
            assert_eq!(parse_frame_rate(text), Err(FrameRateError::Invalid), "{text}");
        }
    }
}
