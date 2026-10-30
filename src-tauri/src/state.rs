//! In-memory, short-TTL storage for an unlocked private key between the
//! `/prepare` and `/sign` calls of one signing session.
//!
//! Deliberately NOT persisted to disk and NOT kept any longer than
//! necessary — cleared on successful sign, on expiry, or when the process
//! exits. TTL matches the backend session's own ~15min window (see
//! `functions/src/signing/session.ts`'s `SESSION_TTL_MS` in the main repo)
//! so a stale agent-side entry can never outlive the session it belongs to.
//!
//! Each entry also carries the per-session `agent_token` handed out in the
//! `/prepare` response — `/sign` must present it back as a secondary
//! session-binding check. This is NOT the primary defense against the
//! signature-oracle finding (an attacker driving both `/prepare` and `/sign`
//! reads the token out of the `/prepare` response); that is the backend's
//! Ed25519 signature over the digest, verified in `server.rs::handle_sign`
//! before this key is ever taken.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use openssl::pkey::{PKey, Private};

use crate::mutex_ext::LockOrRecover;

const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

pub struct PendingSignature {
    pub private_key: PKey<Private>,
    agent_token: String,
    expires_at: Instant,
}

/// Why `take` failed. Distinct variants so the handler can return an
/// accurate error code without leaking which sessions exist beyond what the
/// caller already proved by knowing the `session_id`.
#[derive(Debug, PartialEq, Eq)]
pub enum TakeError {
    /// No live session for this id (never prepared, expired, or already used).
    NotFound,
    /// Session exists but the presented `agent_token` doesn't match the one
    /// issued at `/prepare`. The session is deliberately NOT consumed —
    /// the legitimate web app can still complete it, and the 256-bit token
    /// makes brute-forcing via retries infeasible.
    TokenMismatch,
}

pub struct SigningState {
    sessions: Mutex<HashMap<String, PendingSignature>>,
    ttl: Duration,
}

impl Default for SigningState {
    fn default() -> Self {
        Self { sessions: Mutex::new(HashMap::new()), ttl: SESSION_TTL }
    }
}

/// Constant-time byte comparison — avoids leaking how many leading token
/// bytes matched through response timing. Overkill for a 256-bit random
/// token on localhost, but it costs nothing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl SigningState {
    #[cfg(test)]
    fn with_ttl(ttl: Duration) -> Self {
        Self { sessions: Mutex::new(HashMap::new()), ttl }
    }

    pub fn insert(&self, session_id: String, private_key: PKey<Private>, agent_token: String) {
        let mut sessions = self.sessions.lock_or_recover();
        sessions.retain(|_, v| v.expires_at > Instant::now());
        sessions.insert(
            session_id,
            PendingSignature { private_key, agent_token, expires_at: Instant::now() + self.ttl },
        );
    }

    /// Single-use: removes and returns the key if the session exists, is
    /// unexpired, and `agent_token` matches the one issued at `/prepare`.
    /// A token mismatch leaves the session in place (see [`TakeError`]).
    pub fn take(&self, session_id: &str, agent_token: &str) -> Result<PKey<Private>, TakeError> {
        enum Decision {
            NotFound,
            Expired,
            Mismatch,
            Take,
        }

        let mut sessions = self.sessions.lock_or_recover();
        let decision = match sessions.get(session_id) {
            None => Decision::NotFound,
            // Expiry is checked before the token so an expired session can't
            // leak whether a guessed token would have been right.
            Some(entry) if entry.expires_at <= Instant::now() => Decision::Expired,
            Some(entry) if !constant_time_eq(entry.agent_token.as_bytes(), agent_token.as_bytes()) => {
                Decision::Mismatch
            }
            Some(_) => Decision::Take,
        };
        match decision {
            Decision::NotFound => Err(TakeError::NotFound),
            Decision::Expired => {
                sessions.remove(session_id);
                Err(TakeError::NotFound)
            }
            Decision::Mismatch => Err(TakeError::TokenMismatch),
            Decision::Take => {
                let entry = sessions.remove(session_id).expect("entry checked present above");
                Ok(entry.private_key)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;
    use std::thread::sleep;

    fn test_key() -> PKey<Private> {
        let rsa = Rsa::generate(2048).expect("keygen");
        PKey::from_rsa(rsa).expect("pkey wrap")
    }

    #[test]
    fn take_returns_the_inserted_key_with_the_right_token() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "tok-1".into());
        assert!(state.take("session-1", "tok-1").is_ok());
    }

    #[test]
    fn take_is_single_use() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "tok-1".into());
        assert!(state.take("session-1", "tok-1").is_ok());
        assert_eq!(
            state.take("session-1", "tok-1").unwrap_err(),
            TakeError::NotFound,
            "a second take must not return the same key"
        );
    }

    #[test]
    fn take_returns_not_found_for_unknown_session() {
        let state = SigningState::default();
        assert_eq!(state.take("never-inserted", "tok-1").unwrap_err(), TakeError::NotFound);
    }

    #[test]
    fn take_rejects_a_wrong_token_without_consuming_the_session() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "the-real-token".into());
        assert_eq!(
            state.take("session-1", "wrong-token").unwrap_err(),
            TakeError::TokenMismatch,
            "a wrong token must never yield the key"
        );
        // The legitimate caller must still be able to complete the session
        // after an attacker's failed guess.
        assert!(state.take("session-1", "the-real-token").is_ok());
    }

    #[test]
    fn take_rejects_an_empty_token() {
        // `/sign` with no `agent_token` field deserializes to "" — that must
        // behave exactly like any other wrong token.
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "the-real-token".into());
        assert_eq!(state.take("session-1", "").unwrap_err(), TakeError::TokenMismatch);
    }

    #[test]
    fn take_returns_not_found_after_expiry() {
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("session-1".into(), test_key(), "tok-1".into());
        sleep(Duration::from_millis(60));
        assert_eq!(
            state.take("session-1", "tok-1").unwrap_err(),
            TakeError::NotFound,
            "an expired session must not be returned"
        );
    }

    #[test]
    fn expired_session_with_wrong_token_reports_not_found_not_mismatch() {
        // Expiry wins over token comparison — an expired session must not
        // leak whether a guessed token would have been right.
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("session-1".into(), test_key(), "tok-1".into());
        sleep(Duration::from_millis(60));
        assert_eq!(state.take("session-1", "wrong").unwrap_err(), TakeError::NotFound);
    }

    #[test]
    fn insert_prunes_other_expired_sessions() {
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("stale".into(), test_key(), "tok-stale".into());
        sleep(Duration::from_millis(60));
        state.insert("fresh".into(), test_key(), "tok-fresh".into());
        // The stale entry should have been pruned as a side effect of the
        // second insert, not just left around forever.
        assert_eq!(state.take("stale", "tok-stale").unwrap_err(), TakeError::NotFound);
        assert!(state.take("fresh", "tok-fresh").is_ok());
    }

    #[test]
    fn sessions_are_isolated_by_id_and_token() {
        let state = SigningState::default();
        state.insert("session-a".into(), test_key(), "tok-a".into());
        state.insert("session-b".into(), test_key(), "tok-b".into());
        // Tokens are per-session — session-b's token must not open session-a.
        assert_eq!(state.take("session-a", "tok-b").unwrap_err(), TakeError::TokenMismatch);
        assert!(state.take("session-a", "tok-a").is_ok());
        // session-b must still be there — inserting/taking one session must
        // not disturb another.
        assert!(state.take("session-b", "tok-b").is_ok());
    }

    #[test]
    fn constant_time_eq_matches_equal_and_rejects_unequal() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
