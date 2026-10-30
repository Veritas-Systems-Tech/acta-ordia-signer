//! No cross-platform native dialog exists for password/text entry —
//! `tauri-plugin-dialog` only covers message/confirm/file-pick — so a
//! minimal webview window (`dist/passphrase.html`) is used instead. The
//! HTTP handler thread (one per connection since the concurrency fix —
//! see `server.rs`'s `spawn()` doc comment — not a single shared thread
//! anymore) blocks on a plain `std::sync::mpsc` channel until the window's
//! `submit_passphrase`/`cancel_passphrase` command fires. Window creation
//! itself is dispatched onto the main thread via `run_on_main_thread` — UI
//! operations aren't guaranteed thread-safe on every platform (notably
//! macOS).
//!
//! `PassphraseChannel` is keyed by window label, NOT a single shared slot
//! (found by code review right after the concurrency fix shipped): with
//! one thread per connection, more than one `/prepare` can be mid-dialog
//! at once, and a single shared `Option<Sender>` would let a second
//! concurrent prompt silently steal or spuriously cancel a different
//! session's passphrase. Each call to `prompt_passphrase` gets its own
//! uniquely-labeled window and its own map entry, keyed by that label —
//! `submit_passphrase`/`cancel_passphrase` resolve the right sender via
//! the label of the window that actually invoked them (Tauri auto-injects
//! the calling `Window` into any command that asks for one).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder, Window};
use zeroize::Zeroizing;

use crate::mutex_ext::LockOrRecover;

#[derive(Default)]
pub struct PassphraseChannel(pub Mutex<HashMap<String, Sender<Option<Zeroizing<String>>>>>);

static NEXT_WINDOW_ID: AtomicU64 = AtomicU64::new(0);

#[tauri::command]
pub fn submit_passphrase(window: Window, state: tauri::State<PassphraseChannel>, value: String) {
    // Wrap in Zeroizing as early as possible so the plaintext is scrubbed
    // from heap memory on drop instead of lingering in freed allocations
    // (security audit 2026-07-20, finding 2). The serde-deserialized `value`
    // itself is moved (not cloned) into the wrapper.
    let label = window.label().to_string();
    if let Some(tx) = state.0.lock_or_recover().remove(&label) {
        let _ = tx.send(Some(Zeroizing::new(value)));
    }
    let _ = window.close();
}

#[tauri::command]
pub fn cancel_passphrase(window: Window, state: tauri::State<PassphraseChannel>) {
    let label = window.label().to_string();
    if let Some(tx) = state.0.lock_or_recover().remove(&label) {
        let _ = tx.send(None);
    }
    let _ = window.close();
}

/// Opens a passphrase window (its own, uniquely-labeled instance — see
/// module doc) and blocks the calling thread until the user submits or
/// cancels, or a 5-minute timeout elapses. Returns `None` on
/// cancel/timeout — the caller must treat that as "no passphrase
/// provided," never as an empty-string passphrase. The returned value is
/// zeroized on drop. On timeout, also removes this call's own entry from
/// the shared map so an abandoned prompt doesn't linger there forever.
pub fn prompt_passphrase(app: &AppHandle) -> Option<Zeroizing<String>> {
    let label = format!("passphrase-{}", NEXT_WINDOW_ID.fetch_add(1, Ordering::SeqCst));
    let (tx, rx) = mpsc::channel();
    {
        let state = app.state::<PassphraseChannel>();
        state.0.lock_or_recover().insert(label.clone(), tx);
    }

    let app_for_main = app.clone();
    let label_for_window = label.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = WebviewWindowBuilder::new(&app_for_main, label_for_window, WebviewUrl::App("passphrase.html".into()))
            .title("Acta Ordia Signer")
            .inner_size(360.0, 240.0)
            .resizable(false)
            .center()
            .always_on_top(true)
            .build();
    });

    let result = rx.recv_timeout(Duration::from_secs(5 * 60)).ok().flatten();
    app.state::<PassphraseChannel>().0.lock_or_recover().remove(&label);
    result
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
        // Fails to compile if PassphraseChannel's inner map stops carrying
        // Sender<Option<Zeroizing<String>>> values.
        let (tx, _rx) = mpsc::channel::<Option<Zeroizing<String>>>();
        let mut map = HashMap::new();
        map.insert("passphrase-0".to_string(), tx);
        let _channel = PassphraseChannel(Mutex::new(map));
    }

    #[test]
    fn concurrent_prompts_get_independent_map_entries_not_a_shared_slot() {
        // Regression guard for the concurrency-fix-era bug: two "in flight"
        // prompts must not collide on the same key. Doesn't drive the real
        // GUI/thread path (that needs a live Tauri app) — just proves the
        // data structure itself can hold more than one entry at once,
        // unlike the single `Option<Sender>` slot this replaced.
        let (tx1, _rx1) = mpsc::channel::<Option<Zeroizing<String>>>();
        let (tx2, _rx2) = mpsc::channel::<Option<Zeroizing<String>>>();
        let channel = PassphraseChannel::default();
        channel.0.lock().unwrap().insert("passphrase-0".to_string(), tx1);
        channel.0.lock().unwrap().insert("passphrase-1".to_string(), tx2);
        assert_eq!(channel.0.lock().unwrap().len(), 2);

        // Resolving one by label must not disturb the other.
        let removed = channel.0.lock().unwrap().remove("passphrase-0");
        assert!(removed.is_some());
        assert_eq!(channel.0.lock().unwrap().len(), 1);
        assert!(channel.0.lock().unwrap().contains_key("passphrase-1"));
    }
}
