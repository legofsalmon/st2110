//! Minimum, maximum and mean, over a whole capture and for each second of it, as
//! RP 2110-25 §4.2 reports measurements.

/// Nanoseconds in a second.
pub(crate) const NANOS: i128 = 1_000_000_000;

/// The minimum, maximum and mean of a measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Stats {
    /// How many values there were.
    pub count: u64,
    /// The smallest.
    pub min: f64,
    /// The largest.
    pub max: f64,
    /// The mean.
    pub mean: f64,
}

/// Gathers values into [`Stats`].
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Accumulator {
    count: u64,
    min: f64,
    max: f64,
    sum: f64,
}

impl Accumulator {
    pub(crate) fn add(&mut self, value: f64) {
        if self.count == 0 {
            (self.min, self.max) = (value, value);
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.count += 1;
        self.sum += value;
    }

    pub(crate) fn stats(&self) -> Option<Stats> {
        (self.count > 0).then(|| Stats {
            count: self.count,
            min: self.min,
            max: self.max,
            mean: self.sum / self.count as f64,
        })
    }
}

/// Values gathered for each whole second of the timeline.
#[derive(Debug)]
pub(crate) struct Seconds<T> {
    done: Vec<(i64, T)>,
    current: Option<(i64, T)>,
}

impl<T> Default for Seconds<T> {
    fn default() -> Self {
        Self { done: Vec::new(), current: None }
    }
}

impl<T: Default> Seconds<T> {
    /// The window for the second that `t`, in nanoseconds, falls in. A time earlier than
    /// the current window, as when interfaces' packets interleave, stays in it.
    pub(crate) fn at(&mut self, t: i128) -> &mut T {
        let second = t.div_euclid(NANOS) as i64;
        if self.current.as_ref().is_none_or(|(current, _)| second > *current) {
            self.done.extend(self.current.take());
            self.current = Some((second, T::default()));
        }
        &mut self.current.as_mut().expect("just set").1
    }

    pub(crate) fn finish(mut self) -> Vec<(i64, T)> {
        self.done.extend(self.current.take());
        self.done
    }
}

/// How often something went wrong, when it first did, and the worst case.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Tally {
    pub(crate) count: u64,
    pub(crate) first: Option<i128>,
    /// The largest or smallest value seen, as the caller counts worst.
    pub(crate) worst: Option<f64>,
}

impl Tally {
    pub(crate) fn hit(&mut self, t: i128) {
        self.count += 1;
        self.first.get_or_insert(t);
    }

    /// Counts a case whose size is `value`, keeping the largest.
    pub(crate) fn hit_max(&mut self, t: i128, value: f64) {
        self.hit(t);
        self.worst = Some(self.worst.map_or(value, |worst| worst.max(value)));
    }

    /// Counts a case whose size is `value`, keeping the smallest.
    pub(crate) fn hit_min(&mut self, t: i128, value: f64) {
        self.hit(t);
        self.worst = Some(self.worst.map_or(value, |worst| worst.min(value)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gathers_values() {
        let mut a = Accumulator::default();
        assert_eq!(a.stats(), None);
        for v in [3.0, -1.0, 4.0] {
            a.add(v);
        }
        assert_eq!(a.stats(), Some(Stats { count: 3, min: -1.0, max: 4.0, mean: 2.0 }));
    }

    #[test]
    fn splits_into_seconds() {
        let mut seconds: Seconds<Accumulator> = Seconds::default();
        seconds.at(1_500_000_000).add(1.0);
        seconds.at(1_999_999_999).add(2.0);
        seconds.at(3_000_000_000).add(3.0);
        // Late by a little: kept in the current second.
        seconds.at(2_999_999_000).add(4.0);
        let done = seconds.finish();
        assert_eq!(done.iter().map(|(s, a)| (*s, a.stats().unwrap().count)).collect::<Vec<_>>(), [(1, 2), (3, 2)]);
    }
}
