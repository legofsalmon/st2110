//! Watching a stream as it arrives: a [`Monitor`] takes frames and progress from the
//! thread that receives, and keeps the newest for a window on another thread to show.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::receive::{Report, Sink};
use crate::video::FrameInfo;

/// What has arrived, for a window to show.
#[derive(Default)]
pub struct Latest {
    /// The newest frame's pixel groups.
    pub frame: Vec<u8>,
    /// Whether the window has yet to show that frame.
    pub fresh: bool,
    /// Frames that arrived.
    pub frames: u64,
    /// Those of them that arrived incomplete, not counting any that the start or end
    /// of receiving cut off.
    pub incomplete: u64,
    /// The packets those were missing.
    pub missing: u64,
    /// Whether a frame has arrived whole.
    pub whole: bool,
    /// When the last frame arrived.
    pub last: Option<Instant>,
    /// What the receiver had found when it last reported its progress.
    pub report: Option<Report>,
    /// Whether receiving has stopped.
    pub ended: bool,
}

/// Hands frames from the thread that receives to the one that shows them: each frame,
/// whole or with packets missing, where the frames before it show through, but not
/// those the start or end of receiving cut off, which leave the top or bottom of the
/// picture unsent.
///
/// A shared reference is the [`Sink`] to receive into.
pub struct Monitor {
    latest: Mutex<Latest>,
    arrived: Condvar,
    wake: Box<dyn Fn() + Send + Sync>,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new(|| {})
    }
}

impl Monitor {
    /// A monitor that calls `wake` whenever a frame or progress arrives, such as to ask
    /// a window to draw.
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self { latest: Mutex::default(), arrived: Condvar::new(), wake: Box::new(wake) }
    }

    /// What has arrived.
    pub fn lock(&self) -> MutexGuard<'_, Latest> {
        self.latest.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What has arrived, once there is a frame the window has yet to show or `timeout`
    /// has passed.
    pub fn wait(&self, timeout: Duration) -> MutexGuard<'_, Latest> {
        let latest = self.lock();
        if latest.fresh {
            return latest;
        }
        let waited = self.arrived.wait_timeout_while(latest, timeout, |latest| !latest.fresh);
        waited.unwrap_or_else(PoisonError::into_inner).0
    }

    /// Marks receiving as stopped, with what the receiver found in the end.
    pub fn end(&self, report: Option<Report>) {
        let mut latest = self.lock();
        latest.ended = true;
        if report.is_some() {
            latest.report = report;
        }
        drop(latest);
        self.arrived.notify_all();
        (self.wake)();
    }
}

impl Sink for &Monitor {
    fn frame(&mut self, info: &FrameInfo, pixels: &[u8]) {
        let mut latest = self.lock();
        latest.frames += 1;
        latest.last = Some(Instant::now());
        latest.whole |= info.whole;
        if info.cut {
            return;
        }
        if !info.whole {
            latest.incomplete += 1;
            latest.missing += u64::from(info.missing);
        }
        latest.frame.clear();
        latest.frame.extend_from_slice(pixels);
        latest.fresh = true;
        drop(latest);
        self.arrived.notify_all();
        (self.wake)();
    }

    fn progress(&mut self, report: &Report) {
        self.lock().report = Some(report.clone());
        (self.wake)();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;

    use super::*;

    fn info(whole: bool, cut: bool, missing: u32) -> FrameInfo {
        FrameInfo {
            timestamp: 0,
            packets: 10 - missing,
            missing,
            filled: 0,
            whole,
            cut,
            first_arrival: 0,
            last_arrival: 0,
            first_sequence: 0,
            last_sequence: 0,
        }
    }

    #[test]
    fn hands_over_each_frame_that_receiving_did_not_cut_off() {
        let woken = Arc::new(AtomicU32::new(0));
        let monitor = {
            let woken = Arc::clone(&woken);
            Monitor::new(move || {
                woken.fetch_add(1, Ordering::Relaxed);
            })
        };
        let mut sink = &monitor;
        // Cut off by the start of receiving, which leaves the top of the picture unsent.
        sink.frame(&info(false, true, 4), &[1; 8]);
        assert!(!monitor.lock().fresh);
        // Incomplete, and shown all the same, for a stream that always loses a packet or
        // two would otherwise show nothing.
        sink.frame(&info(false, false, 2), &[2; 8]);
        let latest = monitor.lock();
        assert_eq!((latest.fresh, &latest.frame[..], latest.whole), (true, &[2; 8][..], false));
        drop(latest);
        sink.frame(&info(true, false, 0), &[3; 8]);
        // Cut off by the end: the window keeps the frame before it.
        sink.frame(&info(false, true, 5), &[4; 8]);
        let latest = monitor.lock();
        assert_eq!((&latest.frame[..], latest.whole), (&[3; 8][..], true));
        assert_eq!((latest.frames, latest.incomplete, latest.missing), (4, 1, 2));
        drop(latest);
        sink.progress(&Report { passed: 40, ..Report::default() });
        assert_eq!(monitor.lock().report.as_ref().map(|r| r.passed), Some(40));
        // Two frames shown, and the progress.
        assert_eq!(woken.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn waits_for_a_frame_from_another_thread() {
        let monitor = Arc::new(Monitor::default());
        let started = Instant::now();
        assert!(!monitor.wait(Duration::from_millis(20)).fresh);
        assert!(started.elapsed() >= Duration::from_millis(15));
        let receiving = {
            let monitor = Arc::clone(&monitor);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                (&*monitor).frame(&info(true, false, 0), &[7; 4]);
            })
        };
        let latest = monitor.wait(Duration::from_secs(5));
        assert_eq!((latest.fresh, &latest.frame[..]), (true, &[7; 4][..]));
        drop(latest);
        receiving.join().unwrap();
        monitor.end(None);
        assert!(monitor.lock().ended);
    }
}
