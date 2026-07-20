//! Crash/error reporting — a separate Sentry project from the main
//! acta-ordia app (different runtime, different audience: this one runs on
//! end-user machines we have no other visibility into).
//!
//! Hard rule: only static, whitelisted error *codes* are ever sent — never
//! the `message` half of an `ErrorResponse` (which can contain OpenSSL error
//! strings or io::Error text embedding a local file path, which can embed
//! the OS username), never the passphrase, never `.p12`/certificate bytes,
//! never the acta title (attacker/user-controlled free text). Panics are
//! reported automatically by the `panic` feature using Sentry's own
//! backtrace capture — the same "no local variable values in the message"
//! discipline applies there implicitly, since we never `.expect()`/`panic!()`
//! with sensitive interpolated data (verified in the 2026-07-20 security
//! audit's "panic safety" section).
//!
//! DSN is not a secret — it only identifies which project events land in,
//! same reasoning as the main repo's `functions/src/sentry.ts`.

const DSN: &str =
    "https://4a7feae7ac674bb3d1baba5a7f166b13@o4511168105545728.ingest.us.sentry.io/4511770055606273";

pub fn init() -> Option<sentry::ClientInitGuard> {
    if DSN.starts_with("REPLACE_WITH") {
        eprintln!("acta-ordia-signer: Sentry DSN not configured, crash reporting disabled");
        return None;
    }
    Some(sentry::init((
        DSN,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            send_default_pii: false,
            ..Default::default()
        },
    )))
}

/// Reports a known, coarse failure category — e.g. `"invalid_certificate"`,
/// `"read_failed"`, `"timeout"`. `code` must always be a static string
/// literal from the call site, never anything built from request/file data.
pub fn report(code: &'static str) {
    sentry::capture_message(code, sentry::Level::Error);
}
