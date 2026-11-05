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
//! backtrace capture. Every event passes through `scrub_event` first
//! (2026-11-04): a forced-panic probe showed Sentry attaches the machine's
//! hostname as `server_name` even with `send_default_pii: false`, and a
//! panic message is sent verbatim, so a future `unwrap()` on an io error
//! could carry a local path (and the OS username inside it). The hostname
//! is dropped, and panic messages are replaced by a fixed string; the
//! backtrace (function names, file and line) is what remains for debugging.
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
            before_send: Some(std::sync::Arc::new(|event| {
                if is_enabled() {
                    Some(scrub_event(event))
                } else {
                    None
                }
            })),
            ..Default::default()
        },
    )))
}

/// Fixed replacement for a panic's message, which can embed local data.
pub(crate) const PANIC_MESSAGE_WITHHELD: &str = "panic (message withheld)";

/// Strips what Sentry attaches on its own that identifies the machine or user.
/// Pure (no global state) so it can be unit tested.
pub(crate) fn scrub_event(
    mut event: sentry::protocol::Event<'static>,
) -> sentry::protocol::Event<'static> {
    event.server_name = None; // the machine's hostname
    event.user = None;
    event.request = None;
    for exception in event.exception.values.iter_mut() {
        let is_panic = exception.mechanism.as_ref().is_some_and(|m| m.ty == "panic");
        if is_panic {
            exception.value = Some(PANIC_MESSAGE_WITHHELD.to_string());
        }
    }
    event
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentry::protocol::{Event, Exception, Mechanism, Values};

    fn panic_event() -> Event<'static> {
        Event {
            server_name: Some("IgorBondiman".into()),
            exception: Values::from(vec![Exception {
                ty: "panic".into(),
                value: Some(
                    "called `Result::unwrap()` on an `Err` value: \"cannot open /home/maria/Documents/cert.p12\""
                        .into(),
                ),
                mechanism: Some(Mechanism { ty: "panic".into(), handled: Some(false), ..Default::default() }),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn scrub_drops_the_hostname() {
        assert!(scrub_event(panic_event()).server_name.is_none());
    }

    #[test]
    fn scrub_replaces_a_panic_message_with_a_fixed_string() {
        let event = scrub_event(panic_event());
        let value = event.exception.values[0].value.as_deref().unwrap();
        assert_eq!(value, PANIC_MESSAGE_WITHHELD);
        assert!(!value.contains("maria") && !value.contains("cert.p12"));
        // the exception type and mechanism survive, so Sentry still groups it as a panic
        assert_eq!(event.exception.values[0].ty, "panic");
    }

    #[test]
    fn scrub_leaves_a_static_code_message_alone() {
        let event = Event { message: Some("invalid_certificate".into()), ..Default::default() };
        assert_eq!(scrub_event(event).message.as_deref(), Some("invalid_certificate"));
    }

    #[test]
    fn scrub_leaves_a_non_panic_exception_value_alone() {
        let mut event = panic_event();
        event.exception.values[0].mechanism = None;
        let event = scrub_event(event);
        assert!(event.exception.values[0].value.as_deref().unwrap().contains("cannot open"));
    }
}
