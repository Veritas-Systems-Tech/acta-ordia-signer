//! Local HTTP listener the web app talks to (127.0.0.1 only — never bound
//! to a public interface). This is the Doc_13 §3.2 localhost fallback path;
//! the `actaordia-signer://` deep-link handler is a later pass.
//!
//! `GET /health`, `POST /prepare`, `POST /sign` — see protocol.rs for the
//! full two-phase contract and why it's two calls, not one.
//!
//! Compile-verified (2026-07-18) — see the main repo's memory notes on
//! what that does and doesn't prove. Still never run against a real
//! ICP-Brasil certificate or a real signing session end to end.

use std::io::Read;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::VerifyingKey;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::x509::X509;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tiny_http::{Header, Method, Response, Server};
use zeroize::Zeroizing;

use crate::activity::SignerActivity;
use crate::passphrase::prompt_passphrase;
use crate::picker_memory::{last_certificate_dir, remember_certificate_path};
use crate::protocol::signed_message::{self, Reject};
use crate::protocol::{ErrorResponse, HealthResponse, PrepareRequest, PrepareResponse, SignDigestRequest, SignDigestResponse};
use crate::state::{SigningState, TakeError};

const PORT: u16 = 7734;
/// The Vite dev-server origin is only trusted in debug builds — port 5173
/// is an extremely common local dev port used by unrelated projects, so a
/// release build must never accept it (security audit 2026-07-20, finding 4).
#[cfg(debug_assertions)]
const ALLOWED_ORIGINS: &[&str] = &["https://app.actaordia.com", "http://localhost:5173"];
#[cfg(not(debug_assertions))]
const ALLOWED_ORIGINS: &[&str] = &["https://app.actaordia.com"];

/// JSON payloads on `/prepare` and `/sign` are tiny (a few hundred bytes) —
/// cap reads so a local process can't exhaust memory with a multi-GB POST
/// body (security audit 2026-07-20, finding 6).
const MAX_BODY_BYTES: u64 = 16 * 1024;

/// Bound on how long the confirm dialog / file picker may sit unanswered
/// before the request fails — matches `prompt_passphrase`'s own 5-minute
/// bound, so one abandoned dialog can't wedge the single-threaded HTTP
/// listener forever (security audit 2026-07-20, finding 7).
const DIALOG_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Longest `acta_title` shown in the OS confirm dialog. Anything longer is
/// truncated — a title is a label, not a document.
const MAX_TITLE_CHARS: usize = 120;

/// Blocks browser-JS CSRF only: no `OPTIONS` handler exists, so browsers
/// block non-simple cross-origin requests at CORS preflight, and simple
/// requests from unlisted origins are rejected here. This is NOT a defense
/// against other local processes — any non-browser client can spoof the
/// Origin header. That gap is closed by verifying the backend's Ed25519
/// signature over the digest in `handle_sign` (a local process can't forge
/// it without the backend's private key), not by this check and not by the
/// secondary `agent_token`.
fn is_origin_allowed(origin: Option<&str>) -> bool {
    origin.map(|o| ALLOWED_ORIGINS.contains(&o)).unwrap_or(false)
}

/// 256-bit random token from the OS CSPRNG, base64-encoded. Returned by
/// `/prepare` and required back on `/sign` as a secondary, non-load-bearing
/// session-binding convenience. It does NOT close the signature-oracle
/// finding on its own — an attacker driving both calls reads it out of the
/// `/prepare` response — so the real protection is the backend Ed25519
/// signature verified in `handle_sign`.
fn generate_agent_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(BASE64.encode(bytes))
}

/// Sanitizes an attacker-influencable title for display in the OS confirm
/// dialog: strips control characters and Unicode bidi/invisible formatting
/// characters (RTL overrides, zero-width chars) that could spoof or obscure
/// the dialog text, then caps the length (security audit 2026-07-20,
/// finding 1's social-engineering note).
fn sanitize_title(title: &str) -> String {
    const FORBIDDEN: &[char] = &[
        '\u{200B}', '\u{200C}', '\u{200D}', // zero-width space/non-joiner/joiner
        '\u{200E}', '\u{200F}', // LRM / RLM
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // bidi embeds/overrides
        '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // bidi isolates
        '\u{061C}', // Arabic letter mark
        '\u{FEFF}', // BOM / zero-width no-break space
    ];
    let filtered: Vec<char> = title.chars().filter(|c| !c.is_control() && !FORBIDDEN.contains(c)).collect();
    let truncated = filtered.len() > MAX_TITLE_CHARS;
    let cleaned: String = filtered.into_iter().take(MAX_TITLE_CHARS).collect();
    if truncated {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

// Standard DER prefix for a SHA-256 DigestInfo (RFC 8017) — prepended to the
// raw 32-byte digest before the raw RSA PKCS1v1.5 sign. Same constant used
// on the backend's test harness (functions/src/__tests__/pki-split-digest.test.ts)
// so both sides agree on the padding shape.
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Ed25519 public key (raw 32 bytes, hex) whose private half lives only in the
/// backend's Google Secret Manager (`PKI_DIGEST_SIGNING_PRIVATE_KEY`). Before
/// signing anything, the agent verifies the backend's signature over the tagged
/// signed message (`protocol::signed_message`: domain prefix, session id,
/// certificate fingerprint, expiry, digest) against this key — so a local process cannot feed the agent an
/// attacker-chosen digest and use it as a signature oracle (that would require
/// the backend's private key, which no local attacker has). A public key is
/// safe to embed in an open-source binary.
const PKI_DIGEST_PUBLIC_KEY_HEX: &str =
    "058c2dffc33c87246b5108e8cc64a75b4e9ad18da0b339a65037fe69b949a57d";

/// Decodes a 64-char hex string into exactly 32 bytes.
fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// The embedded production verifying key. Built from the hardcoded constant —
/// a bad edit fails loudly at first use (and there's a test asserting it
/// decodes), so `expect` is appropriate for a compile-time-known constant.
fn production_verifying_key() -> VerifyingKey {
    let bytes = decode_hex_32(PKI_DIGEST_PUBLIC_KEY_HEX)
        .expect("embedded PKI digest public key must be valid 32-byte hex");
    VerifyingKey::from_bytes(&bytes)
        .expect("embedded PKI digest public key must be a valid Ed25519 point")
}

/// The verifying key `/sign` checks against. Production always uses the real
/// embedded key. Test builds swap in a per-binary ephemeral key so the HTTP
/// regression tests can produce valid backend-style digest signatures without
/// the (Secret-Manager-only) production private key — this NEVER weakens the
/// shipped binary, which only ever trusts `production_verifying_key()`.
#[cfg(not(test))]
fn active_digest_verifying_key() -> VerifyingKey {
    production_verifying_key()
}
#[cfg(test)]
fn active_digest_verifying_key() -> VerifyingKey {
    test_digest_signing_key().verifying_key()
}

/// Per-test-binary ephemeral Ed25519 signing key, generated once from the OS
/// CSPRNG. Stands in for the backend's Secret-Manager private key so tests can
/// mint valid digest signatures; its public half is what `active_digest_
/// verifying_key()` trusts under `#[cfg(test)]`. Compiled out of release.
#[cfg(test)]
fn test_digest_signing_key() -> &'static ed25519_dalek::SigningKey {
    use ed25519_dalek::SigningKey;
    static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom for test digest key");
        SigningKey::from_bytes(&seed)
    })
}

pub fn spawn(app: AppHandle) {
    thread::spawn(move || {
        let server = match Server::http(("127.0.0.1", PORT)) {
            Ok(server) => server,
            Err(err) => {
                eprintln!("acta-ordia-signer: failed to bind 127.0.0.1:{PORT}: {err}");
                return;
            }
        };
        println!("acta-ordia-signer: listening on http://127.0.0.1:{PORT}");

        // One thread per connection, not one request at a time. A blocking
        // `/prepare` (file picker / passphrase / confirm dialog, up to
        // `DIALOG_TIMEOUT` = 5 minutes) used to starve every other request
        // on this same accept loop, including `/health` — a user with a
        // signing dialog open in one tab would see the agent reported as
        // "not detected" from a second tab, purely because the single
        // accept thread was blocked, not because anything was actually
        // down. `SigningState`/`SignerActivity` are already `Mutex`/atomic-
        // protected internally (they had to be — this loop already ran on
        // a thread separate from Tauri's main thread even before this
        // change), so concurrent handlers are safe. `tiny_http::Request`
        // is documented as `Send` specifically for this pattern. Unbounded
        // (no thread-pool cap): this binds to 127.0.0.1 only, for a single
        // local browser session — not a public-facing server where
        // connection-flood resource exhaustion would be a real concern.
        for request in server.incoming_requests() {
            let app = app.clone();
            thread::spawn(move || {
                let mut request = request;
                let origin = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Origin"))
                    .map(|h| h.value.as_str().to_string());
                let origin_allowed = is_origin_allowed(origin.as_deref());
                let method = request.method().clone();
                let url = request.url().to_string();
                let signing_state = app.state::<SigningState>();
                let activity = app.state::<SignerActivity>();
                // Held for the whole request — this is what the quit-
                // confirmation dialog checks, not SigningState's 15-minute
                // session map (see activity.rs's module doc for why those
                // are different things).
                let _in_flight = (url != "/health").then(|| activity.enter_request());

                let response = route(
                    &method,
                    &url,
                    origin_allowed,
                    || read_body_capped(&mut request),
                    signing_state.inner(),
                    activity.inner(),
                    |body| handle_prepare(&app, body),
                );

                let _ = request.respond(response);
            });
        }
    });
}

/// The pure request-routing decision, split out of `spawn`'s accept loop so
/// the security-relevant path (origin gate → body cap → token-checked
/// `/sign`) can be driven end-to-end in tests without a live Tauri app or a
/// GUI dialog. `spawn` supplies the real `read_body`/`prepare` closures and
/// the managed `SigningState`; the routing/authorization logic here is the
/// same in production and under test.
///
/// `prepare` is a closure (not an inline call) only because `/prepare` needs
/// the `AppHandle` for its confirm dialog / file picker — everything else
/// (`/health`, the origin rejection, the `/sign` token check, the 404) is
/// fully exercised by the HTTP regression tests below.
fn route(
    method: &Method,
    url: &str,
    origin_allowed: bool,
    read_body: impl FnOnce() -> String,
    signing_state: &SigningState,
    activity: &SignerActivity,
    prepare: impl FnOnce(&str) -> tiny_http::ResponseBox,
) -> tiny_http::ResponseBox {
    match (method, url) {
        (Method::Get, "/health") => json_response(
            &HealthResponse { status: "ok", version: env!("CARGO_PKG_VERSION") },
            200,
        ),
        (Method::Post, "/prepare") if origin_allowed => {
            let body = read_body();
            prepare(&body)
        }
        (Method::Post, "/sign") if origin_allowed => {
            let body = read_body();
            handle_sign(signing_state, activity, &body)
        }
        (Method::Post, "/prepare") | (Method::Post, "/sign") => json_response(
            &ErrorResponse::new("origin_not_allowed", "This agent only accepts requests from the Acta Ordia web app."),
            403,
        ),
        _ => Response::from_string("Not found").with_status_code(404).boxed(),
    }
}

/// Reads the request body with a hard byte cap — an oversized body is
/// simply cut off, which then fails JSON parsing with a 400 instead of
/// exhausting memory.
fn read_body_capped(request: &mut tiny_http::Request) -> String {
    let mut body = String::new();
    let _ = request.as_reader().take(MAX_BODY_BYTES).read_to_string(&mut body);
    body
}

/// A `/prepare` failure: static code, static message, fixed status. Never
/// built from OS, serde, OpenSSL, path or certificate text.
struct PrepareFailure {
    code: &'static str,
    message: &'static str,
    status: u16,
}

impl PrepareFailure {
    const INVALID_REQUEST: Self =
        Self { code: "invalid_request", message: "The signing request body is malformed.", status: 400 };
    const INVALID_PATH: Self =
        Self { code: "invalid_path", message: "The selected file path could not be used.", status: 500 };
    const READ_FAILED: Self =
        Self { code: "read_failed", message: "The certificate file could not be read.", status: 500 };
    const INVALID_CERTIFICATE: Self =
        Self { code: "invalid_certificate", message: "The selected file is not a valid .p12 certificate.", status: 422 };
    const ENCODE_FAILED: Self =
        Self { code: "encode_failed", message: "The certificate could not be encoded.", status: 500 };
    const TOKEN_GENERATION_FAILED: Self =
        Self { code: "token_generation_failed", message: "A session token could not be generated.", status: 500 };

    fn respond(&self) -> tiny_http::ResponseBox {
        json_response(&ErrorResponse::new(self.code, self.message), self.status)
    }
}

fn read_certificate_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, PrepareFailure> {
    std::fs::read(path).map(Zeroizing::new).map_err(|_| PrepareFailure::READ_FAILED)
}

fn parse_pkcs12_der(der: &[u8]) -> Result<Pkcs12, PrepareFailure> {
    Pkcs12::from_der(der).map_err(|_| PrepareFailure::INVALID_CERTIFICATE)
}

fn handle_prepare(app: &AppHandle, body: &str) -> tiny_http::ResponseBox {
    let req: PrepareRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        // Static text only: serde's error text can quote the offending value.
        Err(_) => {
            crate::telemetry::report("prepare_invalid_request");
            return PrepareFailure::INVALID_REQUEST.respond();
        }
    };

    let (pick_tx, pick_rx) = mpsc::channel();
    let mut file_dialog = app.dialog().file().add_filter("PKCS#12 Certificate", &["p12", "pfx"]);
    // Best-effort convenience, not certificate detection — pre-seeds the
    // picker at the directory of whichever .p12 was last selected on this
    // machine, so the user doesn't re-browse to the same file every single
    // signature. Silently skipped if nothing's remembered yet.
    if let Some(dir) = last_certificate_dir(app) {
        file_dialog = file_dialog.set_directory(dir);
    }
    file_dialog.pick_file(move |picked| {
        let _ = pick_tx.send(picked);
    });
    let picked = match pick_rx.recv_timeout(DIALOG_TIMEOUT) {
        Ok(p) => p,
        Err(_) => {
            crate::telemetry::report("file_picker_timeout");
            app.state::<SignerActivity>().record("failed: timeout");
            return json_response(&ErrorResponse::new("timeout", "The certificate picker timed out."), 408);
        }
    };
    let Some(file_path) = picked else {
        app.state::<SignerActivity>().record("failed: no_certificate");
        return json_response(&ErrorResponse::new("no_certificate", "No certificate file was selected."), 422);
    };
    let path = match file_path.into_path() {
        Ok(p) => p,
        Err(_) => {
            crate::telemetry::report("invalid_path");
            app.state::<SignerActivity>().record("failed: invalid_path");
            return PrepareFailure::INVALID_PATH.respond();
        }
    };
    remember_certificate_path(app, &path);
    // Zeroizing: scrub the raw .p12 from heap memory on drop (finding 2).
    let p12_bytes = match read_certificate_file(&path) {
        Ok(b) => b,
        Err(f) => {
            crate::telemetry::report("read_failed");
            app.state::<SignerActivity>().record("failed: read_failed");
            return f.respond();
        }
    };

    let Some(passphrase) = prompt_passphrase(app) else {
        app.state::<SignerActivity>().record("cancelled: passphrase");
        return json_response(&ErrorResponse::new("cancelled", "Passphrase entry was cancelled."), 409);
    };

    let pkcs12 = match parse_pkcs12_der(&p12_bytes) {
        Ok(p) => p,
        Err(f) => {
            crate::telemetry::report("invalid_certificate_der");
            app.state::<SignerActivity>().record("failed: invalid_certificate");
            return f.respond();
        }
    };
    let parsed = match pkcs12.parse2(&passphrase) {
        Ok(p) => p,
        Err(_) => {
            app.state::<SignerActivity>().record("failed: wrong_password");
            return json_response(&ErrorResponse::new("wrong_password", "Incorrect certificate password."), 422);
        }
    };
    let (Some(cert), Some(private_key)) = (parsed.cert, parsed.pkey) else {
        crate::telemetry::report("certificate_missing_cert_or_key");
        app.state::<SignerActivity>().record("failed: invalid_certificate");
        return json_response(&ErrorResponse::new("invalid_certificate", "The .p12 file has no certificate/key pair."), 422);
    };

    // Sanitized immediately, before it's used anywhere: a .p12's CN is
    // fully attacker-controlled (anyone can mint a self-signed cert with
    // any CN string, including bidi-override/zero-width tricks), unlike
    // the comment this replaced assumed. It's the one line whose whole job
    // is letting the user confirm WHOSE identity is about to sign, so it
    // gets the same treatment as acta_title.
    let subject_cn = sanitize_title(&subject_common_name(&cert).unwrap_or_default());

    // Confirmation happens here, after the certificate is parsed, so the
    // dialog can show WHICH identity (ICP-Brasil CN encodes "Name:CPF" or
    // "Name:CNPJ") is about to sign, not just the acta title. Showing the
    // title alone — the original order — let a user approve a signature
    // without ever seeing whose certificate it would carry.
    let (confirm_tx, confirm_rx) = mpsc::channel();
    let dialog_subject = if subject_cn.is_empty() { "unknown subject".to_string() } else { subject_cn.clone() };
    app.dialog()
        .message(format!(
            "Acta Ordia is requesting your signature for \"{}\", using the certificate for:\n{}\n\nContinue?",
            sanitize_title(&req.acta_title),
            dialog_subject
        ))
        .title("Sign with Certificate")
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancel)
        .show(move |confirmed| {
            let _ = confirm_tx.send(confirmed);
        });
    match confirm_rx.recv_timeout(DIALOG_TIMEOUT) {
        Ok(true) => {}
        Ok(false) => {
            app.state::<SignerActivity>().record("cancelled: confirm");
            return json_response(&ErrorResponse::new("cancelled", "Signing was cancelled by the user."), 409)
        }
        Err(_) => {
            crate::telemetry::report("confirm_dialog_timeout");
            app.state::<SignerActivity>().record("failed: timeout");
            return json_response(&ErrorResponse::new("timeout", "The confirmation dialog timed out."), 408);
        }
    }

    let mut chain_der_base64 = Vec::new();
    let cert_fingerprint = match cert.to_der().map_err(|_| ()).and_then(|der| {
        let fp = leaf_fingerprint(&der).map_err(|_| ())?;
        chain_der_base64.push(BASE64.encode(der));
        Ok(fp)
    }) {
        Ok(fp) => fp,
        Err(()) => {
            app.state::<SignerActivity>().record("failed: encode_failed");
            return PrepareFailure::ENCODE_FAILED.respond();
        }
    };
    if let Some(ca_stack) = parsed.ca {
        for ca_cert in ca_stack.iter() {
            if let Ok(der) = ca_cert.to_der() {
                chain_der_base64.push(BASE64.encode(der));
            }
        }
    }

    let agent_token = match generate_agent_token() {
        Ok(t) => t,
        Err(_) => {
            app.state::<SignerActivity>().record("failed: token_generation_failed");
            return PrepareFailure::TOKEN_GENERATION_FAILED.respond();
        }
    };
    app.state::<SigningState>().insert(req.session_id, private_key, agent_token.clone(), cert_fingerprint);
    app.state::<SignerActivity>().record("prepared");

    json_response(
        &PrepareResponse { certificate_chain_base64: chain_der_base64, subject_cn, agent_token },
        200,
    )
}

fn handle_sign(signing_state: &SigningState, activity: &SignerActivity, body: &str) -> tiny_http::ResponseBox {
    handle_sign_with_clock(signing_state, activity, body, now_unix)
}

/// `handle_sign` with an injectable clock (unix seconds, `None` = unreadable).
fn handle_sign_with_clock(
    signing_state: &SigningState,
    activity: &SignerActivity,
    body: &str,
    clock: impl Fn() -> Option<u64>,
) -> tiny_http::ResponseBox {
    let req: SignDigestRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        // Static text only: serde's error text can quote the offending value.
        Err(_) => {
            return json_response(
                &ErrorResponse::new("invalid_request", "The signing request body is malformed."),
                400,
            )
        }
    };

    // Static codes and messages only: nothing from the request is echoed back.
    let reject = |activity: &SignerActivity, r: Reject| {
        activity.record(format!("failed: {}", r.code()));
        json_response(&ErrorResponse::new(r.code(), r.message()), r.status())
    };

    if req.signed_message_version != signed_message::PROTOCOL_VERSION {
        return reject(activity, Reject::UnsupportedProtocol);
    }

    let digest: [u8; 32] = match BASE64.decode(&req.bytes_to_sign_base64).ok().and_then(|d| d.try_into().ok()) {
        Some(d) => d,
        None => {
            return json_response(&ErrorResponse::new("invalid_digest", "Expected a 32-byte SHA-256 digest."), 400)
        }
    };
    let claimed_fingerprint = match signed_message::parse_fingerprint_hex(&req.cert_fingerprint_sha256_hex) {
        Ok(f) => f,
        Err(r) => return reject(activity, r),
    };

    // The load-bearing check: rebuild the tagged message from what we were
    // handed and verify the backend's Ed25519 signature over it before doing
    // anything that consumes state. The message binds the domain prefix,
    // session id, certificate fingerprint, expiry and digest, so a captured
    // signature is useless for another session, another certificate, or after
    // expiry, and a local process cannot use the agent as a signature oracle.
    // A failure here rejects WITHOUT consuming the single-use session.
    //
    // Reported to Sentry: this is also the only signal that would ever catch
    // a deployed-key mismatch (the embedded PKI_DIGEST_PUBLIC_KEY_HEX not
    // actually pairing with the backend's real Secret Manager private key) —
    // that failure mode is otherwise completely silent and would 403 every
    // single real signing attempt forever (see pending-user-actions memory).
    let message = signed_message::build_message(&req.session_id, &claimed_fingerprint, req.expires_at_unix, &digest);
    if let Err(r) = signed_message::verify_signature(&active_digest_verifying_key(), &message, &req.digest_signature_base64) {
        // A bad signature is attacker-triggerable, so Sentry gets at most one
        // event per BAD_SIGNATURE_REPORT_INTERVAL_SECS; the rest stay local.
        if bad_signature_limiter().allow(monotonic_secs()) {
            crate::telemetry::report("invalid_digest_signature");
        } else {
            eprintln!("invalid_digest_signature (not reported: rate-limited)");
        }
        return reject(activity, r);
    }
    // Fail closed: without a readable clock, expiry cannot be enforced.
    let now = match clock() {
        Some(n) => n,
        None => return reject(activity, Reject::ClockUnavailable),
    };
    if let Err(r) = signed_message::check_expiry(req.expires_at_unix, now) {
        return reject(activity, r);
    }

    // The fingerprint is compared against the certificate actually unlocked
    // at /prepare (inside `take`), not merely against what the request says.
    let private_key = match signing_state.take(&req.session_id, &req.agent_token, &claimed_fingerprint) {
        Ok(key) => key,
        Err(TakeError::NotFound) => {
            return json_response(
                &ErrorResponse::new("session_not_found", "No prepared signing session for this sessionId (expired, already used, or /prepare was never called)."),
                404,
            )
        }
        Err(TakeError::TokenMismatch) => {
            return json_response(
                &ErrorResponse::new("invalid_agent_token", "The agent_token is missing or does not match the one issued by /prepare for this session."),
                403,
            )
        }
        Err(TakeError::FingerprintMismatch) => return reject(activity, Reject::FingerprintMismatch),
    };

    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + digest.len());
    digest_info.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&digest);

    let signature = match sign_digest_info(&private_key, &digest_info) {
        Ok(sig) => sig,
        Err(_) => {
            crate::telemetry::report("sign_failed");
            activity.record("failed: sign_failed");
            return json_response(
                &ErrorResponse::new("sign_failed", "The signing operation failed. Start the signing again."),
                500,
            );
        }
    };

    activity.record("signed");
    json_response(&SignDigestResponse { signature_base64: BASE64.encode(signature) }, 200)
}

/// SHA-256 of a certificate's DER encoding.
fn leaf_fingerprint(der: &[u8]) -> Result<[u8; 32], String> {
    let h = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), der).map_err(|e| e.to_string())?;
    h.as_ref().try_into().map_err(|_| "unexpected SHA-256 length".to_string())
}

/// Unix seconds, or `None` if the clock is before the epoch (or exactly at
/// it) — callers must fail closed rather than treat that as time zero.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .filter(|&s| s > 0)
}

/// Minimum spacing between Sentry reports of an invalid digest signature.
const BAD_SIGNATURE_REPORT_INTERVAL_SECS: u64 = 10 * 60;

/// At most one `allow() == true` per interval, per process.
struct ReportLimiter {
    interval_secs: u64,
    last: std::sync::Mutex<Option<u64>>,
}

impl ReportLimiter {
    const fn new(interval_secs: u64) -> Self {
        Self { interval_secs, last: std::sync::Mutex::new(None) }
    }
    /// `now` is any monotonic seconds counter.
    fn allow(&self, now: u64) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match *last {
            Some(t) if now.saturating_sub(t) < self.interval_secs => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }
}

fn bad_signature_limiter() -> &'static ReportLimiter {
    static L: ReportLimiter = ReportLimiter::new(BAD_SIGNATURE_REPORT_INTERVAL_SECS);
    &L
}

/// Seconds since first call; immune to wall-clock changes.
fn monotonic_secs() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new()  ;
    START.get_or_init(std::time::Instant::now).elapsed().as_secs()
}

/// Raw RSA PKCS1v1.5 sign over an already-built DigestInfo — NOT a hashing
/// sign call (that would double-hash). Mirrors the backend test harness's
/// `crypto.privateEncrypt({padding: RSA_PKCS1_PADDING}, digestInfo)` — see
/// this repo's own memory notes on why `crypto.sign(null, ...)` silently
/// produces the wrong result for this exact operation. The `openssl` crate
/// doesn't expose `private_encrypt` directly on `PKey`, only on `Rsa`, so
/// this goes through `.rsa()`.
fn sign_digest_info(private_key: &PKey<openssl::pkey::Private>, digest_info: &[u8]) -> Result<Vec<u8>, String> {
    let rsa = private_key.rsa().map_err(|e| e.to_string())?;
    let mut sig = vec![0u8; rsa.size() as usize];
    let len = rsa
        .private_encrypt(digest_info, &mut sig, Padding::PKCS1)
        .map_err(|e| e.to_string())?;
    sig.truncate(len);
    Ok(sig)
}

fn subject_common_name(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
}

fn json_response<T: serde::Serialize>(body: &T, status: u16) -> tiny_http::ResponseBox {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::from_string(json)
        .with_status_code(status)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::{hash, MessageDigest};
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;
    use std::io::Write;
    use std::net::TcpStream;
    use std::sync::Arc;

    fn test_keypair() -> (PKey<Private>, Rsa<Private>) {
        let rsa = Rsa::generate(2048).expect("keygen");
        let pkey = PKey::from_rsa(rsa.clone()).expect("pkey wrap");
        (pkey, rsa)
    }

    fn test_key() -> PKey<Private> {
        test_keypair().0
    }

    // ----- Real end-to-end HTTP regression harness --------------------------
    //
    // These tests spin up the *actual* `tiny_http` server on an ephemeral
    // port and drive it with a raw TCP HTTP client, so the origin gate, the
    // 16KB body cap, the token-checked `/sign` path, and the 404 all get
    // exercised over the wire — a future refactor that reopens the signature
    // oracle (finding 1) or drops the body cap (finding 6) fails a test here
    // rather than shipping silently.
    //
    // The accept loop mirrors `spawn`'s exactly *except* it can't hold a real
    // `AppHandle`, so it reuses the production `route`/`read_body_capped`/
    // `is_origin_allowed` and stubs only the `/prepare` closure (which needs a
    // GUI confirm dialog + file picker + passphrase window and therefore can't
    // run headlessly — see `prepare_success_path_needs_a_gui` note below). The
    // security-relevant routing/authorization is the same code path as prod.

    /// Boots a real `tiny_http` server backed by `state` and returns its port.
    /// The `/prepare` stub is never reached by these tests (they only send
    /// bad-origin `/prepare`, which is rejected at the gate before `prepare`
    /// is called) — it returns 500 so a regression that *did* reach it is loud.
    fn spawn_test_server(state: Arc<SigningState>) -> u16 {
        let server = Server::http(("127.0.0.1", 0)).expect("bind ephemeral port");
        let port = server.server_addr().to_ip().expect("ip addr").port();
        thread::spawn(move || {
            // No test here inspects activity tracking directly — it only
            // needs to exist so `route()`'s real signature runs unchanged.
            let activity = SignerActivity::default();
            for mut request in server.incoming_requests() {
                let origin = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Origin"))
                    .map(|h| h.value.as_str().to_string());
                let origin_allowed = is_origin_allowed(origin.as_deref());
                let method = request.method().clone();
                let url = request.url().to_string();
                let response = route(
                    &method,
                    &url,
                    origin_allowed,
                    || read_body_capped(&mut request),
                    &state,
                    &activity,
                    |_body| {
                        json_response(
                            &ErrorResponse::new("prepare_unreached", "the /prepare GUI path is never driven in tests"),
                            500,
                        )
                    },
                );
                let _ = request.respond(response);
            }
        });
        port
    }

    /// Mirrors `spawn()`'s real per-connection-thread concurrency (unlike
    /// `spawn_test_server` above, which predates that fix and is still
    /// single-threaded — fine for every other test here, since none of
    /// them depend on two requests overlapping). Used only by the test
    /// proving a slow `/prepare` no longer starves `/health`. `prepare_delay`
    /// stands in for a real blocking GUI dialog.
    fn spawn_concurrent_test_server(
        state: Arc<SigningState>,
        activity: Arc<SignerActivity>,
        prepare_delay: Duration,
    ) -> u16 {
        let server = Server::http(("127.0.0.1", 0)).expect("bind ephemeral port");
        let port = server.server_addr().to_ip().expect("ip addr").port();
        thread::spawn(move || {
            for request in server.incoming_requests() {
                let state = state.clone();
                let activity = activity.clone();
                thread::spawn(move || {
                    let mut request = request;
                    let origin = request
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Origin"))
                        .map(|h| h.value.as_str().to_string());
                    let origin_allowed = is_origin_allowed(origin.as_deref());
                    let method = request.method().clone();
                    let url = request.url().to_string();
                    let _in_flight = (url != "/health").then(|| activity.enter_request());
                    let response = route(
                        &method,
                        &url,
                        origin_allowed,
                        || read_body_capped(&mut request),
                        &state,
                        &activity,
                        |_body| {
                            thread::sleep(prepare_delay);
                            json_response(
                                &ErrorResponse::new("prepare_unreached", "slow stub for the concurrency test"),
                                500,
                            )
                        },
                    );
                    let _ = request.respond(response);
                });
            }
        });
        port
    }

    /// Sends one raw HTTP request and returns `(status_code, body)`. Uses
    /// `Connection: close` so the server closes the socket after responding
    /// and `read_to_end` reaches EOF; a read timeout keeps a hung test from
    /// wedging the suite.
    fn http_send(port: u16, raw_request: &[u8]) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("set timeout");
        stream.write_all(raw_request).expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read response");
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    /// Builds a raw `POST` with an optional `Origin` header and a body.
    fn post(path: &str, origin: Option<&str>, body: &str) -> Vec<u8> {
        let origin_line = origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default();
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{origin_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The one allowed production origin — used as the attacker's *spoofed*
    /// Origin in these tests, which is exactly the point of finding 1: any
    /// local process can set this header, so it must not be sufficient on its
    /// own to obtain a signature.
    const APP_ORIGIN: &str = "https://app.actaordia.com";

    /// The 32-byte SHA-256-shaped digest used across these tests.
    const TEST_DIGEST: [u8; 32] = [0x11u8; 32];

    /// Fingerprint the test sessions are "unlocked" with.
    const TEST_FP: [u8; 32] = [0x22u8; 32];

    fn now_secs() -> u64 {
        now_unix().expect("test clock")
    }

    fn fp_hex(fp: &[u8; 32]) -> String {
        fp.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A backend-style Ed25519 signature over the tagged signed message —
    /// produced with the per-binary test key that `active_digest_verifying_key`
    /// trusts under `#[cfg(test)]`.
    fn signed_message_b64(session_id: &str, fp: &[u8; 32], expires: u64, digest: &[u8; 32]) -> String {
        use ed25519_dalek::Signer;
        let msg = signed_message::build_message(session_id, fp, expires, digest);
        BASE64.encode(test_digest_signing_key().sign(&msg).to_bytes())
    }

    /// Full `/sign` body from explicit parts, so tests can corrupt one field.
    #[allow(clippy::too_many_arguments)]
    fn sign_body_with(
        session_id: &str,
        agent_token: Option<&str>,
        version: u32,
        fp_hex_claim: &str,
        expires: u64,
        digest: &[u8; 32],
        signature_b64: &str,
    ) -> String {
        let token_field = agent_token.map(|t| format!(r#","agent_token":"{t}""#)).unwrap_or_default();
        format!(
            r#"{{"session_id":"{session_id}","bytes_to_sign_base64":"{}","digest_signature_base64":"{signature_b64}","signed_message_version":{version},"cert_fingerprint_sha256_hex":"{fp_hex_claim}","expires_at_unix":{expires}{token_field}}}"#,
            BASE64.encode(digest),
        )
    }

    /// Builds a `/sign` body with a fully VALID signed message for
    /// `TEST_FP`/`TEST_DIGEST`, expiring in 120 s — so tests exercising the
    /// token/session logic reach it instead of stopping at an earlier gate.
    fn sign_body(session_id: &str, agent_token: Option<&str>) -> String {
        let expires = now_secs() + 120;
        sign_body_with(
            session_id,
            agent_token,
            signed_message::PROTOCOL_VERSION,
            &fp_hex(&TEST_FP),
            expires,
            &TEST_DIGEST,
            &signed_message_b64(session_id, &TEST_FP, expires, &TEST_DIGEST),
        )
    }

    #[test]
    fn http_health_is_ungated_and_reports_the_version() {
        let port = spawn_test_server(Arc::new(SigningState::default()));
        let req = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, body) = http_send(port, req);
        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""), "body was: {body}");
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn http_health_is_not_starved_by_a_slow_concurrent_prepare() {
        // Regression test for the race the user's code review surfaced:
        // before the per-connection-thread fix, a single accept-loop thread
        // meant a blocking `/prepare` (real GUI dialogs can take up to
        // DIALOG_TIMEOUT = 5 minutes) starved every other request,
        // including `/health` — so a signing dialog open in one tab made
        // the agent look "not detected" from a second tab, even though it
        // was running fine.
        const PREPARE_DELAY: Duration = Duration::from_millis(400);
        let port = spawn_concurrent_test_server(
            Arc::new(SigningState::default()),
            Arc::new(SignerActivity::default()),
            PREPARE_DELAY,
        );

        // Fire the slow /prepare in the background and deliberately don't
        // wait for it — it's only here to occupy a request-handling slot
        // for PREPARE_DELAY, standing in for a real blocked GUI dialog.
        thread::spawn(move || {
            let req = post("/prepare", Some(APP_ORIGIN), "{}");
            let _ = http_send(port, &req);
        });
        thread::sleep(Duration::from_millis(50)); // let /prepare actually start

        let start = std::time::Instant::now();
        let health_req = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, body) = http_send(port, health_req);
        let elapsed = start.elapsed();

        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""), "body was: {body}");
        assert!(
            elapsed < PREPARE_DELAY / 2,
            "/health took {elapsed:?} while a slow /prepare was in flight — it should answer immediately, not wait on an unrelated request"
        );
    }

    #[test]
    fn http_signature_oracle_regression_full_flow() {
        // Simulates the critical finding-1 exploit end-to-end over real HTTP.
        // A legitimate `/prepare` (GUI) is stubbed by seeding the session +
        // token the agent would have issued; everything after that is the real
        // wire path.
        let state = Arc::new(SigningState::default());
        state.insert("sess-real".into(), test_key(), "the-real-token".into(), TEST_FP);
        let port = spawn_test_server(state);

        // (b) Attacker replays the session_id with a WRONG token → 403, and
        // the session is NOT consumed. The digest signature is valid, so the
        // request reaches the token check (rather than stopping earlier).
        let wrong = post("/sign", Some(APP_ORIGIN), &sign_body("sess-real", Some("attacker-guess")));
        let (status, body) = http_send(port, &wrong);
        assert_eq!(status, 403, "wrong token must be rejected");
        assert!(body.contains("invalid_agent_token"), "body was: {body}");

        // The legitimate caller with the CORRECT token still succeeds — proof
        // the failed attempt above did not consume the single-use session.
        let good = post("/sign", Some(APP_ORIGIN), &sign_body("sess-real", Some("the-real-token")));
        let (status, body) = http_send(port, &good);
        assert_eq!(status, 200, "correct token after a failed guess must still sign");
        assert!(body.contains("signature_base64"), "body was: {body}");
    }

    #[test]
    fn http_sign_with_no_token_field_is_rejected_cleanly_not_500() {
        // (c) A `/sign` with the `agent_token` field entirely absent must be a
        // clean 403 (empty token != real token), never a panic/500.
        let state = Arc::new(SigningState::default());
        state.insert("sess-notoken".into(), test_key(), "the-real-token".into(), TEST_FP);
        let port = spawn_test_server(state);

        let body = post("/sign", Some(APP_ORIGIN), &sign_body("sess-notoken", None));
        let (status, resp) = http_send(port, &body);
        assert_eq!(status, 403, "missing token must be 403, not 500/panic");
        assert!(resp.contains("invalid_agent_token"), "body was: {resp}");
    }

    #[test]
    fn http_sign_for_unknown_session_is_404_not_a_crash() {
        // (d) A completely unrelated session_id with any token → 404.
        let port = spawn_test_server(Arc::new(SigningState::default()));
        let body = post("/sign", Some(APP_ORIGIN), &sign_body("no-such-session", Some("whatever")));
        let (status, resp) = http_send(port, &body);
        assert_eq!(status, 404);
        assert!(resp.contains("session_not_found"), "body was: {resp}");
    }

    #[test]
    fn http_origin_alone_cannot_reach_sign_successfully() {
        // Finding 1's whole point: a spoofed-but-allowed Origin gets a request
        // *past the CSRF gate*, but without the per-session token it still
        // cannot obtain a signature. Here a live session exists, the Origin is
        // the real app origin, yet the token is wrong → no signature.
        let state = Arc::new(SigningState::default());
        state.insert("sess-x".into(), test_key(), "real".into(), TEST_FP);
        let port = spawn_test_server(state);

        let spoofed = post(
            "/sign",
            Some(APP_ORIGIN), // attacker trivially sets this
            &sign_body("sess-x", Some("not-the-token")),
        );
        let (status, resp) = http_send(port, &spoofed);
        assert_eq!(status, 403, "Origin alone must be insufficient to sign");
        assert!(!resp.contains("signature_base64"), "no signature must be returned");
    }

    #[test]
    fn http_disallowed_origin_is_rejected_before_any_signing() {
        // An unlisted Origin never even reaches the token/dialog path.
        let port = spawn_test_server(Arc::new(SigningState::default()));
        for path in ["/sign", "/prepare"] {
            let body = post(path, Some("https://evil.example.com"), r#"{"session_id":"x"}"#);
            let (status, resp) = http_send(port, &body);
            assert_eq!(status, 403, "{path} from a bad origin must be 403");
            assert!(resp.contains("origin_not_allowed"), "body was: {resp}");
        }
        // No Origin header at all is likewise rejected.
        let no_origin = post("/sign", None, r#"{"session_id":"x"}"#);
        let (status, _) = http_send(port, &no_origin);
        assert_eq!(status, 403);
    }

    #[test]
    fn http_oversized_body_is_capped_and_400_not_ooming() {
        // Finding 6: a body far larger than MAX_BODY_BYTES (16KB) is truncated
        // by the cap, so it fails JSON parsing with a 400 instead of being
        // fully buffered into memory or accepted.
        let state = Arc::new(SigningState::default());
        state.insert("sess-real".into(), test_key(), "real".into(), TEST_FP);
        let port = spawn_test_server(state);

        // 20KB of junk — 4KB past the cap. If the cap were removed this would
        // be read in full; with the cap it's truncated to invalid JSON → 400.
        let huge = "a".repeat(20 * 1024);
        let req = post("/sign", Some(APP_ORIGIN), &huge);
        assert!(req.len() as u64 > MAX_BODY_BYTES, "test body must exceed the cap");
        let (status, resp) = http_send(port, &req);
        assert_eq!(status, 400, "oversized/garbage body must be a 400");
        assert!(resp.contains("invalid_request"), "body was: {resp}");
    }

    #[test]
    fn http_unknown_route_is_404() {
        let port = spawn_test_server(Arc::new(SigningState::default()));
        let req = b"GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let (status, _) = http_send(port, req);
        assert_eq!(status, 404);
    }

    fn digest_info_for(data: &[u8]) -> Vec<u8> {
        let digest = hash(MessageDigest::sha256(), data).expect("sha256");
        let mut info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + digest.len());
        info.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
        info.extend_from_slice(&digest);
        info
    }

    #[test]
    fn sign_digest_info_produces_a_signature_that_verifies() {
        let (pkey, rsa) = test_keypair();
        let digest_info = digest_info_for(b"a PDF's worth of bytes, hypothetically");

        let signature = sign_digest_info(&pkey, &digest_info).expect("sign");

        // Reverse the raw RSA op with the public key — this is the same
        // "does the signature actually match" check the backend does with
        // forge's publicKey.verify() before ever trusting a returned
        // signature (see complete-signature.ts's fast-fail check).
        let mut recovered = vec![0u8; rsa.size() as usize];
        let len = rsa
            .public_decrypt(&signature, &mut recovered, Padding::PKCS1)
            .expect("public_decrypt");
        assert_eq!(&recovered[..len], digest_info.as_slice());
    }

    #[test]
    fn sign_digest_info_is_deterministic_per_key_and_input() {
        // RSA PKCS1v1.5 signing has no random salt (unlike PSS) — the same
        // key + same input must always produce byte-identical output. If
        // this ever changes it means the padding mode silently changed.
        let (pkey, _rsa) = test_keypair();
        let digest_info = digest_info_for(b"same content, twice");

        let sig1 = sign_digest_info(&pkey, &digest_info).expect("sign 1");
        let sig2 = sign_digest_info(&pkey, &digest_info).expect("sign 2");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_digest_info_differs_across_keys() {
        let (pkey_a, _) = test_keypair();
        let (pkey_b, _) = test_keypair();
        let digest_info = digest_info_for(b"identical content, different signers");

        let sig_a = sign_digest_info(&pkey_a, &digest_info).expect("sign a");
        let sig_b = sign_digest_info(&pkey_b, &digest_info).expect("sign b");
        assert_ne!(sig_a, sig_b, "two different keys must never produce the same signature");
    }

    // ----- Ed25519 digest-signature verification (the real oracle fix) ------

    /// A fresh, throwaway Ed25519 signing key from the OS CSPRNG — stands in
    /// for the backend's Secret-Manager private key in unit tests.
    fn ephemeral_signing_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom");
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[test]
    fn embedded_production_public_key_is_valid() {
        // The shipped constant must decode to a real 32-byte Ed25519 point —
        // a bad edit would otherwise only blow up at first `/sign` in prod.
        assert_eq!(decode_hex_32(PKI_DIGEST_PUBLIC_KEY_HEX).expect("hex").len(), 32);
        let _ = production_verifying_key(); // must not panic
    }

    /// Boots a server with one live session and returns its port.
    fn port_with_session(session: &str) -> u16 {
        let state = Arc::new(SigningState::default());
        state.insert(session.into(), test_key(), "real".into(), TEST_FP);
        spawn_test_server(state)
    }

    fn sign_status(port: u16, body: &str) -> (u16, String) {
        http_send(port, &post("/sign", Some(APP_ORIGIN), body))
    }

    #[test]
    fn http_sign_with_a_signature_from_another_key_is_403_and_does_not_consume_session() {
        use ed25519_dalek::Signer;
        let port = port_with_session("sess-badsig");
        let attacker = ephemeral_signing_key();
        let expires = now_secs() + 120;
        let msg = signed_message::build_message("sess-badsig", &TEST_FP, expires, &TEST_DIGEST);
        let bad = BASE64.encode(attacker.sign(&msg).to_bytes());
        let body = sign_body_with("sess-badsig", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &bad);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");

        let (status, resp) = sign_status(port, &sign_body("sess-badsig", Some("real")));
        assert_eq!(status, 200, "a rejected attempt must not consume the session");
        assert!(resp.contains("signature_base64"), "body was: {resp}");
    }

    #[test]
    fn http_sign_good_message_passes() {
        let port = port_with_session("sess-ok");
        let (status, resp) = sign_status(port, &sign_body("sess-ok", Some("real")));
        assert_eq!(status, 200, "body was: {resp}");
    }

    #[test]
    fn http_sign_wrong_session_id_in_message_fails() {
        // Signature was minted for another session id, replayed under this one.
        let port = port_with_session("sess-a");
        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-OTHER", &TEST_FP, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-a", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");
        assert!(!resp.contains("sess-OTHER") && !resp.contains("sess-a"), "no request data in errors: {resp}");
    }

    #[test]
    fn http_sign_fingerprint_not_matching_unlocked_cert_fails() {
        // The backend legitimately signed a message for a DIFFERENT certificate
        // (valid signature), but the agent unlocked TEST_FP.
        let port = port_with_session("sess-fp");
        let other = [0x33u8; 32];
        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-fp", &other, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-fp", Some("real"), 1, &fp_hex(&other), expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("fingerprint_mismatch"), "body was: {resp}");
        // Not consumed.
        let (status, _) = sign_status(port, &sign_body("sess-fp", Some("real")));
        assert_eq!(status, 200);
    }

    #[test]
    fn http_sign_claimed_fingerprint_differs_from_signed_one_fails() {
        // Request claims the unlocked cert's fingerprint, but the backend
        // signed a message for another cert: rebuilt message differs.
        let port = port_with_session("sess-fp2");
        let other = [0x33u8; 32];
        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-fp2", &other, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-fp2", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");
    }

    #[test]
    fn http_sign_expired_message_fails() {
        let port = port_with_session("sess-exp");
        let expires = now_secs() - (signed_message::EXPIRY_SKEW_SECS + 30);
        let sig = signed_message_b64("sess-exp", &TEST_FP, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-exp", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("signature_expired"), "body was: {resp}");
        // Within skew is still accepted.
        let expires = now_secs() - (signed_message::EXPIRY_SKEW_SECS - 30);
        let sig = signed_message_b64("sess-exp", &TEST_FP, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-exp", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
        assert_eq!(sign_status(port, &body).0, 200);
    }

    #[test]
    fn http_sign_altered_digest_fails() {
        let port = port_with_session("sess-dig");
        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-dig", &TEST_FP, expires, &TEST_DIGEST);
        let altered = [0x99u8; 32];
        let body = sign_body_with("sess-dig", Some("real"), 1, &fp_hex(&TEST_FP), expires, &altered, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");
    }

    #[test]
    fn http_sign_altered_expiry_fails() {
        // Extending the expiry after the fact invalidates the signature.
        let port = port_with_session("sess-ext");
        let signed_exp = now_secs() - 1000;
        let sig = signed_message_b64("sess-ext", &TEST_FP, signed_exp, &TEST_DIGEST);
        let body = sign_body_with("sess-ext", Some("real"), 1, &fp_hex(&TEST_FP), now_secs() + 120, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 403);
        assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");
    }

    #[test]
    fn http_sign_signature_over_bare_digest_or_wrong_prefix_fails() {
        // Legacy behaviour (signature over the bare digest), a message with no
        // domain prefix, and one with a different prefix must all fail.
        use ed25519_dalek::Signer;
        let port = port_with_session("sess-pre");
        let expires = now_secs() + 120;
        let key = test_digest_signing_key();
        let layout = |prefix: &[u8]| {
            let mut m = Vec::new();
            m.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
            m.extend_from_slice(prefix);
            m.extend_from_slice(&("sess-pre".len() as u32).to_be_bytes());
            m.extend_from_slice(b"sess-pre");
            m.extend_from_slice(&TEST_FP);
            m.extend_from_slice(&expires.to_be_bytes());
            m.extend_from_slice(&TEST_DIGEST);
            m
        };
        let no_prefix = {
            let mut m = Vec::new();
            m.extend_from_slice(&("sess-pre".len() as u32).to_be_bytes());
            m.extend_from_slice(b"sess-pre");
            m.extend_from_slice(&TEST_FP);
            m.extend_from_slice(&expires.to_be_bytes());
            m.extend_from_slice(&TEST_DIGEST);
            m
        };
        let candidates: Vec<Vec<u8>> =
            vec![TEST_DIGEST.to_vec(), no_prefix, layout(b"acta-ordia-signer/v0"), layout(b"other-app/v1"), layout(b"")];
        for msg in candidates {
            let sig = BASE64.encode(key.sign(&msg).to_bytes());
            let body = sign_body_with("sess-pre", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
            let (status, resp) = sign_status(port, &body);
            assert_eq!(status, 403);
            assert!(resp.contains("invalid_digest_signature"), "body was: {resp}");
        }
        // Sanity: the correct prefix verifies.
        let good = BASE64.encode(key.sign(&layout(signed_message::DOMAIN_PREFIX)).to_bytes());
        let body = sign_body_with("sess-pre", Some("real"), 1, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &good);
        assert_eq!(sign_status(port, &body).0, 200);
    }

    #[test]
    fn http_sign_missing_or_wrong_protocol_version_is_unsupported_protocol() {
        let port = port_with_session("sess-ver");
        // Old web app: no new fields at all, legacy digest-only signature.
        use ed25519_dalek::Signer;
        let legacy_sig = BASE64.encode(test_digest_signing_key().sign(&TEST_DIGEST).to_bytes());
        let legacy = format!(
            r#"{{"session_id":"sess-ver","bytes_to_sign_base64":"{}","digest_signature_base64":"{legacy_sig}","agent_token":"real"}}"#,
            BASE64.encode(TEST_DIGEST)
        );
        let (status, resp) = sign_status(port, &legacy);
        assert_eq!(status, 400);
        assert!(resp.contains("unsupported_protocol"), "body was: {resp}");

        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-ver", &TEST_FP, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-ver", Some("real"), 2, &fp_hex(&TEST_FP), expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 400);
        assert!(resp.contains("unsupported_protocol"), "body was: {resp}");
    }

    #[test]
    fn http_sign_malformed_fingerprint_is_rejected_statically() {
        let port = port_with_session("sess-bad-fp");
        let expires = now_secs() + 120;
        let sig = signed_message_b64("sess-bad-fp", &TEST_FP, expires, &TEST_DIGEST);
        let body = sign_body_with("sess-bad-fp", Some("real"), 1, "zz-not-hex", expires, &TEST_DIGEST, &sig);
        let (status, resp) = sign_status(port, &body);
        assert_eq!(status, 400);
        assert!(resp.contains("invalid_fingerprint") && !resp.contains("zz-not-hex"), "body was: {resp}");
    }

    #[test]
    fn leaf_fingerprint_is_sha256_of_der() {
        // SHA-256("abc")
        assert_eq!(
            fp_hex(&leaf_fingerprint(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn origin_allowlist_accepts_exact_matches_only() {
        assert!(is_origin_allowed(Some("https://app.actaordia.com")));
        // The Vite dev origin is only in the allowlist for debug builds
        // (finding 4) — tests compile as debug, so it's present here.
        #[cfg(debug_assertions)]
        assert!(is_origin_allowed(Some("http://localhost:5173")));
        #[cfg(not(debug_assertions))]
        assert!(!is_origin_allowed(Some("http://localhost:5173")));
    }

    #[test]
    fn origin_allowlist_rejects_missing_origin() {
        assert!(!is_origin_allowed(None));
    }

    #[test]
    fn allowed_origins_constant_gates_the_dev_port_to_debug_builds() {
        // Finding 4: the Vite dev origin must be present ONLY in debug builds.
        // Rust's test harness normally compiles with debug_assertions on, so
        // the release branch is exercised by running `cargo test --release`
        // (done in this change's verification, output in the report).
        let has_vite = ALLOWED_ORIGINS.contains(&"http://localhost:5173");
        #[cfg(debug_assertions)]
        assert!(has_vite, "debug builds should trust the Vite dev origin");
        #[cfg(not(debug_assertions))]
        assert!(!has_vite, "release builds must NOT trust the Vite dev origin");
        // The production origin is always present, in both build profiles.
        assert!(ALLOWED_ORIGINS.contains(&"https://app.actaordia.com"));
    }

    #[test]
    fn origin_allowlist_rejects_unlisted_origins() {
        assert!(!is_origin_allowed(Some("https://evil.example.com")));
    }

    #[test]
    fn origin_allowlist_rejects_lookalike_and_substring_origins() {
        // A prefix/substring check here would be a real vulnerability — any
        // local process could spoof an Origin header. Confirms the
        // allowlist does exact string equality, not `.starts_with()` /
        // `.contains()`.
        assert!(!is_origin_allowed(Some("https://app.actaordia.com.evil.com")));
        assert!(!is_origin_allowed(Some("https://app.actaordia.com.")));
        assert!(!is_origin_allowed(Some("http://app.actaordia.com")));
    }

    #[test]
    fn subject_common_name_extracts_the_cn() {
        let (pkey, _rsa) = test_keypair();
        let mut builder = X509::builder().expect("builder");
        builder.set_pubkey(&pkey).expect("set pubkey");
        let mut name_builder = openssl::x509::X509NameBuilder::new().expect("name builder");
        name_builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "Test Signer:12345678901").expect("append CN");
        let name = name_builder.build();
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.sign(&pkey, MessageDigest::sha256()).expect("self-sign");
        let cert = builder.build();

        assert_eq!(subject_common_name(&cert), Some("Test Signer:12345678901".to_string()));
    }

    #[test]
    fn subject_cn_from_a_malicious_certificate_is_sanitized_before_display() {
        // Regression test for a real finding: a .p12's CN is fully
        // attacker-controlled (anyone can mint a self-signed cert with any
        // CN string), so handle_prepare must sanitize it the same way it
        // sanitizes acta_title before putting it in the confirm dialog or
        // the PrepareResponse — this confirms subject_common_name's raw
        // output, piped through sanitize_title (what handle_prepare now
        // does), strips the same spoofing tricks acta_title is protected
        // against.
        let (pkey, _rsa) = test_keypair();
        let mut builder = X509::builder().expect("builder");
        builder.set_pubkey(&pkey).expect("set pubkey");
        let mut name_builder = openssl::x509::X509NameBuilder::new().expect("name builder");
        let evil_cn = "Jo\u{202E}nhoD\u{200B}e\u{FEFF}";
        name_builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, evil_cn).expect("append CN");
        let name = name_builder.build();
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.sign(&pkey, MessageDigest::sha256()).expect("self-sign");
        let cert = builder.build();

        let raw_cn = subject_common_name(&cert).expect("CN should be present");
        assert_eq!(raw_cn, evil_cn, "sanity check: the raw CN really does carry the attack chars");

        let sanitized = sanitize_title(&raw_cn);
        for forbidden in ['\u{202E}', '\u{200B}', '\u{FEFF}'] {
            assert!(!sanitized.contains(forbidden), "forbidden char {forbidden:?} leaked through sanitization: {sanitized:?}");
        }
    }

    #[test]
    fn generate_agent_token_is_random_and_decodes_to_32_bytes() {
        let a = generate_agent_token().expect("token a");
        let b = generate_agent_token().expect("token b");
        assert_ne!(a, b, "two tokens must never collide");
        assert_eq!(BASE64.decode(&a).expect("base64").len(), 32);
        assert_eq!(BASE64.decode(&b).expect("base64").len(), 32);
    }

    #[test]
    fn sanitize_title_passes_ordinary_titles_through() {
        assert_eq!(sanitize_title("Q3 Board Meeting"), "Q3 Board Meeting");
        assert_eq!(sanitize_title("Ata de Reunião — Diretoria"), "Ata de Reunião — Diretoria");
    }

    #[test]
    fn sanitize_title_strips_control_and_bidi_characters() {
        // RTL override + isolates + zero-width chars + C0 controls must all
        // be removed — they can visually spoof or obscure the confirm
        // dialog's text.
        assert_eq!(sanitize_title("abc\u{202E}def"), "abcdef");
        assert_eq!(sanitize_title("a\u{2066}b\u{2069}c"), "abc");
        assert_eq!(sanitize_title("zero\u{200B}width\u{FEFF}"), "zerowidth");
        assert_eq!(sanitize_title("line\nbreak\ttab\rcr"), "linebreaktabcr");
    }

    #[test]
    fn sanitize_title_handles_a_realistic_combined_spoof() {
        // A single realistic attack string mixing several tricks at once: an
        // RTL override to disguise a `.exe` as a document, a wrapping bidi
        // pop, a zero-width space, a BOM, a raw control char, AND an
        // over-length tail — all must be cleaned and capped together, since
        // the real attacker won't politely use one class at a time.
        let evil = format!(
            "Invoice \u{202E}fdp.exe\u{202C}\u{200B}\u{FEFF}\u{0007} URGENT PAY {}",
            "!".repeat(400)
        );
        let cleaned = sanitize_title(&evil);

        // No control chars and none of the invisible/bidi formatting survive.
        assert!(!cleaned.chars().any(|c| c.is_control()), "control chars leaked: {cleaned:?}");
        for forbidden in ['\u{202E}', '\u{202C}', '\u{200B}', '\u{FEFF}', '\u{0007}'] {
            assert!(!cleaned.contains(forbidden), "forbidden char {forbidden:?} leaked");
        }
        // Length is capped (+1 for the ellipsis marker).
        assert!(cleaned.chars().count() <= MAX_TITLE_CHARS + 1);
        assert!(cleaned.ends_with('…'), "over-length spoof must be truncated with an ellipsis");
        // The visible, legitimate prefix survives intact.
        assert!(cleaned.starts_with("Invoice "));
    }

    #[test]
    fn sanitize_title_caps_length_with_ellipsis() {
        let long = "x".repeat(500);
        let sanitized = sanitize_title(&long);
        assert_eq!(sanitized.chars().count(), MAX_TITLE_CHARS + 1); // cap + '…'
        assert!(sanitized.ends_with('…'));
        // Exactly at the cap: untouched, no ellipsis.
        let exact = "y".repeat(MAX_TITLE_CHARS);
        assert_eq!(sanitize_title(&exact), exact);
    }

    #[test]
    fn subject_common_name_is_none_without_a_cn() {
        let (pkey, _rsa) = test_keypair();
        let mut builder = X509::builder().expect("builder");
        builder.set_pubkey(&pkey).expect("set pubkey");
        let name = openssl::x509::X509NameBuilder::new().expect("name builder").build();
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.sign(&pkey, MessageDigest::sha256()).expect("self-sign");
        let cert = builder.build();

        assert_eq!(subject_common_name(&cert), None);
    }

    #[test]
    fn http_sign_malformed_body_does_not_echo_request_values() {
        let port = port_with_session("sess-malformed");
        let body = r#"{"session_id":"s","bytes_to_sign_base64":"x","digest_signature_base64":"x","signed_message_version":1,"cert_fingerprint_sha256_hex":"x","expires_at_unix":"SECRET"}"#;
        let (status, resp) = sign_status(port, body);
        assert_eq!(status, 400);
        assert!(resp.contains("invalid_request") && !resp.contains("SECRET"), "body was: {resp}");
        let body = r#"{"session_id":"s","bytes_to_sign_base64":"x","digest_signature_base64":"x","signed_message_version":"SECRET","cert_fingerprint_sha256_hex":"x","expires_at_unix":1}"#;
        let (status, resp) = sign_status(port, body);
        assert_eq!(status, 400);
        assert!(resp.contains("invalid_request") && !resp.contains("SECRET"), "body was: {resp}");
    }

    #[test]
    fn unreadable_clock_fails_closed_without_consuming_the_session() {
        let state = SigningState::default();
        state.insert("sess-clock".into(), test_key(), "real".into(), TEST_FP);
        let activity = SignerActivity::default();
        let body = sign_body("sess-clock", Some("real"));
        let resp = handle_sign_with_clock(&state, &activity, &body, || None);
        assert_eq!(resp.status_code().0, 500);
        let mut text = String::new();
        resp.into_reader().read_to_string(&mut text).unwrap();
        assert!(text.contains("clock_unavailable"), "body was: {text}");
        // Session still usable with a working clock.
        let resp = handle_sign_with_clock(&state, &activity, &body, now_unix);
        assert_eq!(resp.status_code().0, 200);
    }

    #[test]
    fn expiry_skew_is_pinned_to_sixty_seconds() {
        assert_eq!(signed_message::EXPIRY_SKEW_SECS, 60);
    }

    #[test]
    fn bad_signature_report_limiter_allows_one_per_interval() {
        let l = ReportLimiter::new(600);
        assert!(l.allow(1000), "first is reported");
        assert!(!l.allow(1000));
        assert!(!l.allow(1599));
        assert!(l.allow(1600), "reported again once the interval has passed");
        assert!(!l.allow(1700));
    }

    // Shared cross-language vector: the same constants and expected hex are
    // checked in acta-ordia functions/src/__tests__/signed-message.test.ts.
    // Throwaway seed, never a real key. Expected values generated with node
    // crypto (independent of this code).
    #[test]
    fn shared_vector_matches_the_typescript_side() {
        use ed25519_dalek::{Signer, SigningKey};
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let fp: [u8; 32] = std::array::from_fn(|i| i as u8);
        let digest: [u8; 32] = std::array::from_fn(|i| 255 - i as u8);
        let msg = signed_message::build_message("vector-session-1", &fp, 0x0001020304050607, &digest);
        assert_eq!(fp_hex_vec(&msg), VECTOR_MESSAGE_HEX);
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(fp_hex_vec(key.verifying_key().as_bytes()), VECTOR_PUBLIC_KEY_HEX);
        assert_eq!(fp_hex_vec(&key.sign(&msg).to_bytes()), VECTOR_SIGNATURE_HEX);
        signed_message::verify_signature(&key.verifying_key(), &msg, &BASE64.encode(key.sign(&msg).to_bytes())).unwrap();
    }

    fn fp_hex_vec(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    // Expiry 0x0001020304050607 (not 0x0102030405060708): the TS side uses a JS
    // number, which is exact only below 2^53; this still exercises the high 32 bits.
    const VECTOR_MESSAGE_HEX: &str = "00000014616374612d6f726469612d7369676e65722f763100000010766563746f722d73657373696f6e2d31000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0001020304050607fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0";
    const VECTOR_PUBLIC_KEY_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const VECTOR_SIGNATURE_HEX: &str = "3fc5c1f3eca9ac818876a17795c5a0f365cc8a67f133d9066f499e660c03423c8aa4aa970c7676c07a069eb07802b544b9fec7fcb83360d3d5a66062bdb11a01";

    fn body_text(r: tiny_http::ResponseBox) -> (u16, String) {
        let status = r.status_code().0;
        let mut t = String::new();
        r.into_reader().read_to_string(&mut t).unwrap();
        (status, t)
    }

    #[test]
    fn prepare_failure_responses_are_static_and_keep_codes_and_statuses() {
        for (f, code, status) in [
            (PrepareFailure::INVALID_REQUEST, "invalid_request", 400),
            (PrepareFailure::INVALID_PATH, "invalid_path", 500),
            (PrepareFailure::READ_FAILED, "read_failed", 500),
            (PrepareFailure::INVALID_CERTIFICATE, "invalid_certificate", 422),
            (PrepareFailure::ENCODE_FAILED, "encode_failed", 500),
            (PrepareFailure::TOKEN_GENERATION_FAILED, "token_generation_failed", 500),
        ] {
            let (s, t) = body_text(f.respond());
            assert_eq!(s, status);
            assert!(t.contains(code), "body was: {t}");
        }
    }

    #[test]
    fn prepare_nonexistent_path_does_not_leak_path_or_os_error() {
        let path = std::path::Path::new("/nonexistent-dir-SECRET/cert-SECRET.p12");
        let Err(f) = read_certificate_file(path) else { panic!("must fail") };
        let (s, t) = body_text(f.respond());
        assert_eq!(s, 500);
        for bad in ["SECRET", "nonexistent", "No such file", "os error", "(os error"] {
            assert!(!t.contains(bad), "body leaked {bad}: {t}");
        }
        assert!(t.contains("read_failed"));
    }

    #[test]
    fn prepare_unreadable_file_does_not_leak_path_or_os_error() {
        // A directory cannot be read as a file: a portable stand-in for an unreadable file.
        let dir = std::env::temp_dir().join("signer-SECRET-unreadable");
        std::fs::create_dir_all(&dir).unwrap();
        let Err(f) = read_certificate_file(&dir) else { panic!("must fail") };
        let _ = std::fs::remove_dir(&dir);
        let (s, t) = body_text(f.respond());
        assert_eq!(s, 500);
        for bad in ["SECRET", "signer-", "directory", "os error", "Permission denied"] {
            assert!(!t.contains(bad), "body leaked {bad}: {t}");
        }
    }

    #[test]
    fn prepare_invalid_certificate_does_not_leak_openssl_text() {
        let Err(f) = parse_pkcs12_der(b"SECRET-not-a-p12") else { panic!("must fail") };
        let (s, t) = body_text(f.respond());
        assert_eq!(s, 422);
        for bad in ["SECRET", "error:", "asn1", "ASN1", "openssl", "OpenSSL"] {
            assert!(!t.contains(bad), "body leaked {bad}: {t}");
        }
        assert!(t.contains("invalid_certificate"));
    }

    #[test]
    fn prepare_malformed_body_does_not_echo_values() {
        let body = r#"{"acta_id":"a","session_id":"s","hmac_token":"t","hmac_timestamp":"SECRET","document_hash":"h","acta_title":"x"}"#;
        assert!(serde_json::from_str::<PrepareRequest>(body).is_err(), "fixture must be malformed");
        // handle_prepare maps any parse error to this static response.
        let (s, t) = body_text(PrepareFailure::INVALID_REQUEST.respond());
        assert_eq!(s, 400);
        assert!(!t.contains("SECRET") && !t.contains("expected") && !t.contains("line "), "body was: {t}");
    }
}
