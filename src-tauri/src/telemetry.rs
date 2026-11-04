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
//!
//! Opt-out, default ON, disclosed (2026-11-03): matches the existing
//! autostart philosophy ("a signing tool should just be ready"), but is now
//! disclosed in the first-run notification and surfaced as a "Share crash
//! reports" tray-menu checkbox (`main.rs`), with a read-only mirror in the
//! status popover. `init()` still runs unconditionally at process start,
//! before any `AppHandle` exists, so the persisted preference can't be read
//! at that exact moment — instead every actual emission point (`report()`
//! and the auto-captured panic path, via `before_send`) checks a
//! process-wide `AtomicBool` that defaults to `true` (today's always-on
//! behavior) and gets corrected to the real persisted value once
//! `load_and_cache_preference` runs from `.setup()`, after the app handle
//! exists. Accepted gap: a panic in the narrow window between process
//! start and `.setup()` (Tauri/plugin init, before any signing logic runs)
//! would still report even for an opted-out user, since the cache hasn't
//! loaded yet — never worse than the pre-existing always-on behavior, and
//! not worth the complexity of resolving the app-data directory independently
//! of Tauri just to close an already-inert, pre-signing-logic window.

use std::sync::atomic::{AtomicBool, Ordering};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

const DSN: &str =
    "https://4a7feae7ac674bb3d1baba5a7f166b13@o4511168105545728.ingest.us.sentry.io/4511770055606273";

/// Marker file convention matches `FIRST_RUN_MARKER`/`picker_memory.rs` —
/// absent means enabled, so every existing install (no file yet) keeps
/// today's always-on behavior after this update.
const OPT_OUT_MARKER: &str = "crash_reporting_disabled";

static ENABLED: AtomicBool = AtomicBool::new(true);

fn marker_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_local_data_dir().ok().map(|dir| dir.join(OPT_OUT_MARKER))
}

/// Call once from `.setup()`, after the app handle exists, to replace the
/// default-enabled cache with whatever the user actually last chose.
pub fn load_and_cache_preference(app: &AppHandle) {
    let disabled = marker_path(app).is_some_and(|p| p.exists());
    ENABLED.store(!disabled, Ordering::Relaxed);
}

/// Tray-menu toggle handler. Best-effort persistence, same reasoning as
/// `picker_memory.rs` — a failure to write the marker file just means the
/// choice won't survive a restart, not worth surfacing as an error.
pub fn set_enabled(app: &AppHandle, enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    let Some(path) = marker_path(app) else { return };
    if enabled {
        let _ = std::fs::remove_file(path);
    } else {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, b"");
    }
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

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
            // Covers the auto-captured panic path, not just report() below —
            // dropping here rather than never installing the panic hook at
            // all keeps the kill switch effective even though init() always
            // runs before the real preference is known (see module doc).
            before_send: Some(std::sync::Arc::new(|event| if is_enabled() { Some(event) } else { None })),
            ..Default::default()
        },
    )))
}

/// Reports a known, coarse failure category — e.g. `"invalid_certificate"`,
/// `"read_failed"`, `"timeout"`. `code` must always be a static string
/// literal from the call site, never anything built from request/file data.
pub fn report(code: &'static str) {
    if !is_enabled() {
        return;
    }
    sentry::capture_message(code, sentry::Level::Error);
}
