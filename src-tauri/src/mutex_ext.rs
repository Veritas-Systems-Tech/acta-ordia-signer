//! Poisoning recovery for the signer's long-running shared `Mutex`es.
//!
//! A poisoned `std::sync::Mutex` permanently panics on every future
//! `lock()` call unless explicitly recovered — appropriate for a
//! short-lived CLI tool, wrong for this process. With one thread per HTTP
//! connection (see `server.rs`'s `spawn()`), a single handler panicking
//! while holding `SigningState`'s/`SignerActivity`'s/`PassphraseChannel`'s
//! lock would otherwise cascade into every future concurrent request
//! failing the same way — while `/health` (which touches none of these
//! locks) keeps reporting the agent as healthy, hiding exactly the
//! failure that matters (found by code review right after the
//! concurrency fix shipped).
//!
//! None of the data these locks guard (a session map, an activity ring
//! buffer, a passphrase-channel map) has an invariant a torn write could
//! violate badly enough to justify refusing all future access forever —
//! at worst, a panic mid-operation drops one entry.

use std::sync::{Mutex, MutexGuard};

pub trait LockOrRecover<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockOrRecover<T> for Mutex<T> {
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn recovers_after_a_panic_while_holding_the_lock_instead_of_panicking_forever() {
        let mutex = Arc::new(Mutex::new(0u32));

        let poisoner = Arc::clone(&mutex);
        let _ = thread::spawn(move || {
            let mut guard = poisoner.lock().unwrap();
            *guard = 1;
            panic!("simulated handler panic while holding the lock");
        })
        .join();

        // A plain `.lock()` would now return `Err(PoisonError)`.
        assert!(mutex.lock().is_err());

        // `lock_or_recover` must not panic, and must see whatever state
        // was left (the write before the panic already completed here).
        let guard = mutex.lock_or_recover();
        assert_eq!(*guard, 1);
    }
}
