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
//! Ed25519 signature over the tagged signed message, verified in `server.rs::handle_sign`
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
    /// SHA-256 of the DER of the certificate whose key was unlocked at
    /// `/prepare`. `/sign` requires the backend-signed message to name this
    /// exact fingerprint.
    cert_fingerprint: [u8; 32],
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
    /// The backend-signed message is bound to a different certificate than
    /// the one unlocked for this session. Session NOT consumed.
    FingerprintMismatch,
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

    pub fn insert(
        &self,
        session_id: String,
        private_key: PKey<Private>,
        agent_token: String,
        cert_fingerprint: [u8; 32],
    ) {
        let mut sessions = self.sessions.lock_or_recover();
        sessions.retain(|_, v| v.expires_at > Instant::now());
        sessions.insert(
            session_id,
            PendingSignature { private_key, agent_token, cert_fingerprint, expires_at: Instant::now() + self.ttl },
        );
    }

    /// Single-use: removes and returns the key if the session exists, is
    /// unexpired, and `agent_token` matches the one issued at `/prepare`.
    /// A token mismatch leaves the session in place (see [`TakeError`]).
    pub fn take(
        &self,
        session_id: &str,
        agent_token: &str,
        expected_fingerprint: &[u8; 32],
    ) -> Result<PKey<Private>, TakeError> {
        enum Decision {
            NotFound,
            Expired,
            Mismatch,
            FingerprintMismatch,
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
            Some(entry) if !constant_time_eq(&entry.cert_fingerprint, expected_fingerprint) => {
                Decision::FingerprintMismatch
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
            Decision::FingerprintMismatch => Err(TakeError::FingerprintMismatch),
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

    const FP: [u8; 32] = [0xAB; 32];

    fn test_key() -> PKey<Private> {
        let rsa = Rsa::generate(2048).expect("keygen");
        PKey::from_rsa(rsa).expect("pkey wrap")
    }

    #[test]
    fn take_returns_the_inserted_key_with_the_right_token() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "tok-1".into(), FP);
        assert!(state.take("session-1", "tok-1", &FP).is_ok());
    }

    #[test]
    fn take_is_single_use() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "tok-1".into(), FP);
        assert!(state.take("session-1", "tok-1", &FP).is_ok());
        assert_eq!(
            state.take("session-1", "tok-1", &FP).unwrap_err(),
            TakeError::NotFound,
            "a second take must not return the same key"
        );
    }

    #[test]
    fn take_returns_not_found_for_unknown_session() {
        let state = SigningState::default();
        assert_eq!(state.take("never-inserted", "tok-1", &FP).unwrap_err(), TakeError::NotFound);
    }

    #[test]
    fn take_rejects_a_wrong_token_without_consuming_the_session() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "the-real-token".into(), FP);
        assert_eq!(
            state.take("session-1", "wrong-token", &FP).unwrap_err(),
            TakeError::TokenMismatch,
            "a wrong token must never yield the key"
        );
        // The legitimate caller must still be able to complete the session
        // after an attacker's failed guess.
        assert!(state.take("session-1", "the-real-token", &FP).is_ok());
    }

    #[test]
    fn take_rejects_an_empty_token() {
        // `/sign` with no `agent_token` field deserializes to "" — that must
        // behave exactly like any other wrong token.
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "the-real-token".into(), FP);
        assert_eq!(state.take("session-1", "", &FP).unwrap_err(), TakeError::TokenMismatch);
    }

    #[test]
    fn take_rejects_a_wrong_fingerprint_without_consuming_the_session() {
        let state = SigningState::default();
        state.insert("session-1".into(), test_key(), "tok-1".into(), FP);
        assert_eq!(
            state.take("session-1", "tok-1", &[0xCD; 32]).unwrap_err(),
            TakeError::FingerprintMismatch,
        );
        assert!(state.take("session-1", "tok-1", &FP).is_ok(), "mismatch must not consume the session");
    }

    #[test]
    fn take_returns_not_found_after_expiry() {
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("session-1".into(), test_key(), "tok-1".into(), FP);
        sleep(Duration::from_millis(60));
        assert_eq!(
            state.take("session-1", "tok-1", &FP).unwrap_err(),
            TakeError::NotFound,
            "an expired session must not be returned"
        );
    }

    #[test]
    fn expired_session_with_wrong_token_reports_not_found_not_mismatch() {
        // Expiry wins over token comparison — an expired session must not
        // leak whether a guessed token would have been right.
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("session-1".into(), test_key(), "tok-1".into(), FP);
        sleep(Duration::from_millis(60));
        assert_eq!(state.take("session-1", "wrong", &FP).unwrap_err(), TakeError::NotFound);
    }

    #[test]
    fn insert_prunes_other_expired_sessions() {
        let state = SigningState::with_ttl(Duration::from_millis(20));
        state.insert("stale".into(), test_key(), "tok-stale".into(), FP);
        sleep(Duration::from_millis(60));
        state.insert("fresh".into(), test_key(), "tok-fresh".into(), FP);
        // The stale entry should have been pruned as a side effect of the
        // second insert, not just left around forever.
        assert_eq!(state.take("stale", "tok-stale", &FP).unwrap_err(), TakeError::NotFound);
        assert!(state.take("fresh", "tok-fresh", &FP).is_ok());
    }

    #[test]
    fn sessions_are_isolated_by_id_and_token() {
        let state = SigningState::default();
        state.insert("session-a".into(), test_key(), "tok-a".into(), FP);
        state.insert("session-b".into(), test_key(), "tok-b".into(), FP);
        // Tokens are per-session — session-b's token must not open session-a.
        assert_eq!(state.take("session-a", "tok-b", &FP).unwrap_err(), TakeError::TokenMismatch);
        assert!(state.take("session-a", "tok-a", &FP).is_ok());
        // session-b must still be there — inserting/taking one session must
        // not disturb another.
        assert!(state.take("session-b", "tok-b", &FP).is_ok());
    }

    #[test]
    fn constant_time_eq_matches_equal_and_rejects_unequal() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
