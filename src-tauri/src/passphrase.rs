//! No cross-platform native dialog exists for password/text entry —
//! `tauri-plugin-dialog` only covers message/confirm/file-pick — so a
//! minimal webview window (`dist/passphrase.html`) is used instead. The
//! HTTP handler thread (tiny_http, a plain `std::thread`, not the Tauri
//! main/event-loop thread) blocks on a plain `std::sync::mpsc` channel
//! until the window's `submit_passphrase`/`cancel_passphrase` command
//! fires. Window creation itself is dispatched onto the main thread via
//! `run_on_main_thread` — UI operations aren't guaranteed thread-safe on
//! every platform (notably macOS).
//!
//! ⚠️ Unverified: this module has not been exercised against a real
//! `cargo build` in this environment (blocked on missing system deps — see
//! the main repo's memory). The `run_on_main_thread` API shape should be
//! re-checked against the actual installed `tauri` crate version before
//! trusting this compiles as written.

use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct PassphraseChannel(pub Mutex<Option<Sender<Option<Zeroizing<String>>>>>);

#[tauri::command]
pub fn submit_passphrase(app: AppHandle, state: tauri::State<PassphraseChannel>, value: String) {
    // Wrap in Zeroizing as early as possible so the plaintext is scrubbed
    // from heap memory on drop instead of lingering in freed allocations
    // (security audit 2026-07-20, finding 2). The serde-deserialized `value`
    // itself is moved (not cloned) into the wrapper.
    if let Some(tx) = state.0.lock().expect("passphrase channel mutex poisoned").take() {
        let _ = tx.send(Some(Zeroizing::new(value)));
    }
    close_window(&app);
}

#[tauri::command]
pub fn cancel_passphrase(app: AppHandle, state: tauri::State<PassphraseChannel>) {
    if let Some(tx) = state.0.lock().expect("passphrase channel mutex poisoned").take() {
        let _ = tx.send(None);
    }
    close_window(&app);
}

fn close_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("passphrase") {
        let _ = window.close();
    }
}

/// Opens the passphrase window and blocks the calling thread until the
/// user submits or cancels, or a 5-minute timeout elapses. Returns `None`
/// on cancel/timeout — the caller must treat that as "no passphrase
/// provided," never as an empty-string passphrase. The returned value is
/// zeroized on drop.
pub fn prompt_passphrase(app: &AppHandle) -> Option<Zeroizing<String>> {
    let (tx, rx) = mpsc::channel();
    {
        let state = app.state::<PassphraseChannel>();
        *state.0.lock().expect("passphrase channel mutex poisoned") = Some(tx);
    }

    let app_for_main = app.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = WebviewWindowBuilder::new(&app_for_main, "passphrase", WebviewUrl::App("passphrase.html".into()))
            .title("Acta Ordia Signer")
            .inner_size(360.0, 240.0)
            .resizable(false)
            .center()
            .always_on_top(true)
            .build();
    });

    rx.recv_timeout(Duration::from_secs(5 * 60)).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are compile-time regression guards for finding 2 (passphrase
    // zeroization). They don't run any Tauri code — they simply won't compile
    // if someone changes the sensitive types back to a plain `String`, which
    // would silently reintroduce the "plaintext lingers in freed heap" bug.
    // Freed-memory contents can't be inspected from a test, so pinning the
    // types is the strongest automatic guard available here.

    #[test]
    fn prompt_passphrase_return_type_is_zeroizing() {
        // Fails to compile if the return type stops being Option<Zeroizing<String>>.
        let _typed: fn(&AppHandle) -> Option<Zeroizing<String>> = prompt_passphrase;
    }

    #[test]
    fn passphrase_channel_carries_a_zeroizing_string() {
        // Fails to compile if PassphraseChannel's inner Sender stops carrying
        // Zeroizing<String> (e.g. reverted to Sender<Option<String>>).
        let (tx, _rx) = mpsc::channel::<Option<Zeroizing<String>>>();
        let _channel = PassphraseChannel(Mutex::new(Some(tx)));
    }
}
