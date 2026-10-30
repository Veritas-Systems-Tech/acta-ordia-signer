//! In-memory, never-persisted activity tracking for the status popover
//! (tray left-click) and the quit-confirmation dialog.
//!
//! Two deliberately separate concerns, despite living in one module:
//!   - `InFlightGuard` — a precise "is an HTTP request being handled RIGHT
//!     NOW" counter. NOT the same thing as `SigningState`'s sessions map,
//!     which holds a *prepared-but-unsigned* session for its full 15-minute
//!     TTL — gating the quit dialog on that would warn on every ordinary
//!     quit if the user prepared a signature and forgot about it minutes
//!     ago. This counter only reflects a request literally in `route()`
//!     right now.
//!   - `ActivityLog` — a capped ring buffer of coarse, label-only events
//!     ("prepared", "signed", "cancelled", "failed: <code>") for the status
//!     popover. Same privacy discipline as `telemetry.rs`: no document
//!     content, no certificate subject, no file paths — only what kind of
//!     thing happened and when. Never written to disk; gone on restart.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::mutex_ext::LockOrRecover;
use std::time::SystemTime;

const ACTIVITY_LOG_CAPACITY: usize = 10;

pub struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> InFlightGuard<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(serde::Serialize, Clone)]
pub struct ActivityEntry {
    /// Coarse label only — see module doc. Never document content, never a
    /// certificate subject, never a file path.
    pub label: String,
    /// Milliseconds since Unix epoch — serialized as a number so the status
    /// popover can format it in the user's own locale/timezone.
    pub at_ms: u64,
}

pub struct SignerActivity {
    in_flight: AtomicUsize,
    log: Mutex<VecDeque<ActivityEntry>>,
}

impl Default for SignerActivity {
    fn default() -> Self {
        Self { in_flight: AtomicUsize::new(0), log: Mutex::new(VecDeque::with_capacity(ACTIVITY_LOG_CAPACITY)) }
    }
}

impl SignerActivity {
    /// Call at the very top of handling one HTTP request; drop the guard
    /// when done (or let it fall out of scope) to decrement.
    pub fn enter_request(&self) -> InFlightGuard<'_> {
        InFlightGuard::enter(&self.in_flight)
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn record(&self, label: impl Into<String>) {
        let at_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut log = self.log.lock_or_recover();
        if log.len() >= ACTIVITY_LOG_CAPACITY {
            log.pop_front();
        }
        log.push_back(ActivityEntry { label: label.into(), at_ms });
    }

    pub fn recent(&self) -> Vec<ActivityEntry> {
        self.log.lock_or_recover().iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_guard_increments_on_enter_and_decrements_on_drop() {
        let activity = SignerActivity::default();
        assert_eq!(activity.in_flight_count(), 0);
        {
            let _guard = activity.enter_request();
            assert_eq!(activity.in_flight_count(), 1);
        }
        assert_eq!(activity.in_flight_count(), 0);
    }

    #[test]
    fn nested_requests_count_independently() {
        let activity = SignerActivity::default();
        let g1 = activity.enter_request();
        let g2 = activity.enter_request();
        assert_eq!(activity.in_flight_count(), 2);
        drop(g1);
        assert_eq!(activity.in_flight_count(), 1);
        drop(g2);
        assert_eq!(activity.in_flight_count(), 0);
    }

    #[test]
    fn activity_log_caps_at_capacity_dropping_oldest_first() {
        let activity = SignerActivity::default();
        for i in 0..(ACTIVITY_LOG_CAPACITY + 3) {
            activity.record(format!("event_{i}"));
        }
        let recent = activity.recent();
        assert_eq!(recent.len(), ACTIVITY_LOG_CAPACITY);
        // The oldest 3 (event_0..event_2) must have been evicted.
        assert_eq!(recent.first().unwrap().label, "event_3");
        assert_eq!(recent.last().unwrap().label, format!("event_{}", ACTIVITY_LOG_CAPACITY + 2));
    }
}
