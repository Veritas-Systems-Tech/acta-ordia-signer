//! The tray-left-click / "Status…" menu item popover (ADR pending).
//!
//! Deliberately NOT the dashboard this app doesn't need — there is no
//! persistent certificate state to list (every signature re-opens a fresh
//! file picker; see `picker_memory.rs`'s doc comment). This window exists
//! purely to answer "what has this thing actually done on my machine,"
//! which a tray icon alone can't show. Read-only: no settings live here —
//! "Start at login" stays on the tray menu, not duplicated into a second
//! surface.

use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;

use crate::activity::{ActivityEntry, SignerActivity};

#[derive(Serialize)]
pub struct StatusSnapshot {
    version: &'static str,
    autostart_enabled: bool,
    activity: Vec<ActivityEntry>,
}

#[tauri::command]
pub fn get_signer_status(app: AppHandle, activity: tauri::State<SignerActivity>) -> StatusSnapshot {
    StatusSnapshot {
        version: env!("CARGO_PKG_VERSION"),
        // `is_enabled()` can fail on an unusual platform/permissions setup —
        // reporting "false" rather than erroring the whole popover for what
        // is, worst case, a cosmetically wrong checkbox state elsewhere.
        autostart_enabled: app.autolaunch().is_enabled().unwrap_or(false),
        activity: activity.recent(),
    }
}

/// Opens the status popover, or focuses it if already open. Window creation
/// dispatched onto the main thread, same reasoning as `passphrase.rs`'s
/// window creation (UI operations aren't guaranteed thread-safe on every
/// platform, notably macOS) — this can be called from a tray menu-event or
/// tray-icon-event handler, neither of which is guaranteed to already be
/// the main thread.
pub fn open_status_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("status") {
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let app_for_main = app.clone();
    let _ = app.run_on_main_thread(move || {
        let _ = WebviewWindowBuilder::new(&app_for_main, "status", WebviewUrl::App("status.html".into()))
            .title("Acta Ordia Signer — Status")
            .inner_size(320.0, 420.0)
            .resizable(false)
            .center()
            .build();
    });
}
