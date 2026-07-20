//! Request/response shapes for the local web-app <-> agent handoff.
//!
//! Mirrors the backend split-digest contract (see the main acta-ordia repo,
//! `functions/src/signing/prepare-digest.ts` + `complete-signature.ts`).
//! Kept in sync by hand for now — there is no shared schema package yet.
//!
//! Two round-trips, not one, because the CMS digest depends on which
//! certificate is used: the signer's name gets embedded in the PDF
//! placeholder *before* hashing (see `cms.ts`'s header in the main repo), so
//! the certificate must be chosen and revealed to the backend before a
//! digest can even be computed. The agent can't skip straight to signing.
//!
//!   1. Web app calls the backend's `preparePkiSigningRequest` -> gets a
//!      `sessionId` + `hmacToken`.
//!   2. Web app calls this agent's `POST /prepare` with that session info.
//!      Agent confirms with the user, lets them pick a local certificate
//!      (A1 `.p12` for now, A3/PKCS#11 deferred), and returns only the
//!      public certificate chain — never the private key. The agent keeps
//!      the unlocked private key in memory, keyed by `session_id`, for a
//!      short TTL (matches the backend session's ~15min TTL) so step 4
//!      doesn't need to re-prompt for the passphrase.
//!   3. Web app forwards the certificate chain to the backend's
//!      `preparePkiSignatureDigest`, gets back a pre-hashed SHA-256 digest.
//!   4. Web app calls this agent's `POST /sign` with that digest. Agent
//!      signs it with the private key stashed in step 2 (raw RSA PKCS1v1.5
//!      over the pre-hashed digest — a private-key operation, not a
//!      raw-message sign) and evicts the stashed key — single use.
//!   5. Web app forwards the signature bytes to the backend's
//!      `completePkiSignature` callable, which reconstructs the final CMS
//!      and embeds the PAdES-B signature into the PDF.
//!
//! The agent never receives the PDF, never transmits the private key or
//! passphrase, and never talks to the backend directly — only the
//! authenticated browser does. That's a deliberate boundary: bundling
//! Firebase Auth credentials into a native binary is more attack surface
//! for no real benefit, and it keeps the agent from ever needing to "phone
//! home."

use serde::{Deserialize, Serialize};

/// Body of `POST /prepare`.
///
/// `acta_id`/`hmac_token`/`hmac_timestamp`/`document_hash` are deliberately
/// not read here — the agent never calls the backend itself (Phase 0
/// decision: "agent-never-calls-Functions"), so it has no use for the HMAC
/// token. Verification happens backend-side when the browser separately
/// calls `preparePkiSignatureDigest` with the same token. These fields are
/// kept on the wire for API-shape parity / future audit logging.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PrepareRequest {
    pub acta_id: String,
    pub session_id: String,
    pub hmac_token: String,
    pub hmac_timestamp: i64,
    pub document_hash: String,
    pub acta_title: String,
}

#[derive(Debug, Serialize)]
pub struct PrepareResponse {
    pub certificate_chain_base64: Vec<String>,
    pub subject_cn: String,
    /// Per-session shared secret, freshly generated from the OS CSPRNG on
    /// every successful `/prepare`, echoed back on `/sign` as a secondary
    /// session-binding convenience. It is NOT what closes the signature-oracle
    /// finding: an attacker driving both `/prepare` and `/sign` just reads this
    /// token out of the `/prepare` response. The load-bearing defense is the
    /// backend's Ed25519 signature over the digest (`SignDigestRequest.
    /// digest_signature_base64`), verified against the agent's embedded public
    /// key before signing.
    pub agent_token: String,
}

/// Body of `POST /sign`. `session_id` must match a prior successful
/// `/prepare` call whose stashed key hasn't expired or already been used.
///
/// `digest_signature_base64` is the load-bearing defense: the backend's
/// Ed25519 signature over `bytes_to_sign_base64`, verified against the
/// agent's embedded public key before anything is signed. It is a **required**
/// field with no serde default — a missing digest signature is an explicit
/// deserialize failure (400 `invalid_request`), never a silent bypass, so no
/// local process can drive `/sign` without a real backend-issued signature.
///
/// `agent_token` is a secondary, non-load-bearing session-binding secret (see
/// `PrepareResponse`). It does NOT close the signature-oracle finding on its
/// own — an attacker driving both `/prepare` and `/sign` simply reads the
/// token out of the `/prepare` response — so the Ed25519 check above is what
/// actually protects the private key.
#[derive(Debug, Deserialize)]
pub struct SignDigestRequest {
    pub session_id: String,
    pub bytes_to_sign_base64: String,
    pub digest_signature_base64: String,
    /// Defaults to empty (rather than a serde missing-field 400) so a
    /// missing token gets the explicit `invalid_agent_token` rejection.
    #[serde(default)]
    pub agent_token: String,
}

#[derive(Debug, Serialize)]
pub struct SignDigestResponse {
    pub signature_base64: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: &'static str,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error: &'static str, message: impl Into<String>) -> Self {
        Self { error, message: message.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These lock in the exact wire key names (snake_case, no
    // rename_all/camelCase) that the frontend's `pkiSigning.ts` hand-builds
    // to match — there's no shared schema package, so a drift here would be
    // a silent runtime break (agent returns 400, or the frontend can't read
    // the response) rather than a compile error on either side.

    #[test]
    fn prepare_request_deserializes_expected_snake_case_keys() {
        let json = r#"{
            "acta_id": "acta-1",
            "session_id": "sess-1",
            "hmac_token": "token-1",
            "hmac_timestamp": 1700000000,
            "document_hash": "abc123",
            "acta_title": "Q3 Board Meeting"
        }"#;
        let req: PrepareRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.acta_id, "acta-1");
        assert_eq!(req.session_id, "sess-1");
        assert_eq!(req.hmac_token, "token-1");
        assert_eq!(req.hmac_timestamp, 1700000000);
        assert_eq!(req.document_hash, "abc123");
        assert_eq!(req.acta_title, "Q3 Board Meeting");
    }

    #[test]
    fn prepare_response_serializes_expected_snake_case_keys() {
        let res = PrepareResponse {
            certificate_chain_base64: vec!["cert-a".to_string(), "cert-b".to_string()],
            subject_cn: "Test Signer:12345678901".to_string(),
            agent_token: "tok-1".to_string(),
        };
        let json: serde_json::Value = serde_json::to_value(&res).expect("serialize");
        assert_eq!(json["certificate_chain_base64"], serde_json::json!(["cert-a", "cert-b"]));
        assert_eq!(json["subject_cn"], "Test Signer:12345678901");
        assert_eq!(json["agent_token"], "tok-1");
    }

    #[test]
    fn sign_digest_request_deserializes_expected_snake_case_keys() {
        let json = r#"{"session_id": "sess-1", "bytes_to_sign_base64": "ZGlnZXN0", "digest_signature_base64": "c2ln", "agent_token": "tok-1"}"#;
        let req: SignDigestRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.session_id, "sess-1");
        assert_eq!(req.bytes_to_sign_base64, "ZGlnZXN0");
        assert_eq!(req.digest_signature_base64, "c2ln");
        assert_eq!(req.agent_token, "tok-1");
    }

    #[test]
    fn sign_digest_request_missing_agent_token_defaults_to_empty() {
        // A missing token must still deserialize (so the handler can return
        // the explicit `invalid_agent_token` error instead of a generic
        // serde 400) — and an empty token must never match a real one. The
        // digest signature is still required and present here.
        let json = r#"{"session_id": "sess-1", "bytes_to_sign_base64": "ZGlnZXN0", "digest_signature_base64": "c2ln"}"#;
        let req: SignDigestRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.agent_token, "");
        assert_eq!(req.digest_signature_base64, "c2ln");
    }

    #[test]
    fn sign_digest_request_missing_digest_signature_is_a_deserialize_error() {
        // Unlike agent_token, the digest signature has no serde default — a
        // missing one must fail deserialization (handler → 400 invalid_request),
        // never silently pass as empty.
        let json = r#"{"session_id": "sess-1", "bytes_to_sign_base64": "ZGlnZXN0", "agent_token": "tok-1"}"#;
        let parsed: Result<SignDigestRequest, _> = serde_json::from_str(json);
        assert!(parsed.is_err(), "missing digest_signature_base64 must be a hard error");
    }

    #[test]
    fn sign_digest_response_serializes_expected_snake_case_keys() {
        let res = SignDigestResponse { signature_base64: "c2ln".to_string() };
        let json: serde_json::Value = serde_json::to_value(&res).expect("serialize");
        assert_eq!(json["signature_base64"], "c2ln");
    }

    #[test]
    fn error_response_serializes_error_and_message() {
        let res = ErrorResponse::new("no_certificate", "No certificate file was selected.");
        let json: serde_json::Value = serde_json::to_value(&res).expect("serialize");
        assert_eq!(json["error"], "no_certificate");
        assert_eq!(json["message"], "No certificate file was selected.");
    }
}
