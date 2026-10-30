// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod activity;
mod mutex_ext;
mod passphrase;
mod picker_memory;
mod protocol;
mod server;
mod state;
mod status_window;
mod telemetry;

use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};
use tauri_plugin_autostart::{ManagerExt as AutostartManagerExt, MacosLauncher};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;

use activity::SignerActivity;
use passphrase::{cancel_passphrase, submit_passphrase, PassphraseChannel};
use state::SigningState;

const FIRST_RUN_MARKER: &str = ".first_run_complete";

/// `true` the very first time this is ever called on this machine (the
/// marker file didn't exist yet and was just created), `false` on every
/// later launch. Best-effort in the safe direction: any filesystem error
/// (can't read the app-data dir, can't write the marker) reads as "not
/// first run" — worst case a weird filesystem skips the one-time autostart
/// default and welcome notification, never repeats them indefinitely.
fn mark_first_run_if_new(app: &tauri::AppHandle) -> bool {
    let Ok(dir) = app.path().app_local_data_dir() else { return false };
    let marker = dir.join(FIRST_RUN_MARKER);
    if marker.exists() {
        return false;
    }
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(&marker, b"").is_ok()
}

/// Exits immediately if nothing is in flight. Otherwise asks first — gated
/// on `SignerActivity`'s dedicated in-flight counter, NOT `SigningState`'s
/// sessions map (that holds a prepared-but-unsigned session for its full
/// 15-minute TTL, which would warn on an ordinary quit long after the user
/// forgot about an abandoned signature — see activity.rs's module doc).
fn request_quit(app: &tauri::AppHandle) {
    let in_flight = app.state::<SignerActivity>().in_flight_count();
    if in_flight == 0 {
        app.exit(0);
        return;
    }
    let app_for_confirm = app.clone();
    app.dialog()
        .message(format!(
            "A signature is currently being processed ({in_flight} request{} in flight). Quit anyway?",
            if in_flight == 1 { "" } else { "s" }
        ))
        .title("Quit Acta Ordia Signer")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .show(move |confirmed| {
            if confirmed {
                app_for_confirm.exit(0);
            }
        });
}

/// Flips autostart and keeps the tray checkbox's visual state in sync —
/// `AutoLaunchManager::enable`/`disable` don't touch the menu item
/// themselves, and there's no `app.menu()` accessor to re-fetch it later,
/// so the item is captured by the caller and passed in directly.
fn toggle_autostart(app: &tauri::AppHandle, item: &CheckMenuItem<tauri::Wry>) {
    let Ok(enabled) = app.autolaunch().is_enabled() else { return };
    let result = if enabled { app.autolaunch().disable() } else { app.autolaunch().enable() };
    if result.is_ok() {
        let _ = item.set_checked(!enabled);
    }
}

/// User-triggered check (the "Check for Updates" menu item) — unlike the
/// silent startup check, this one always reports back, including "already
/// up to date" and "couldn't check," and installs + restarts immediately
/// on finding an update rather than just notifying.
fn check_for_updates_now(app: &tauri::AppHandle) {
    let app_for_check = app.clone();
    tauri::async_runtime::spawn(async move {
        let Ok(updater) = app_for_check.updater() else { return };
        match updater.check().await {
            Ok(Some(update)) => {
                if update.download_and_install(|_, _| {}, || {}).await.is_ok() {
                    app_for_check.restart();
                } else {
                    let _ = app_for_check
                        .notification()
                        .builder()
                        .title("Acta Ordia Signer")
                        .body("Found an update but couldn't install it — check your internet connection and try again.")
                        .show();
                }
            }
            Ok(None) => {
                let _ = app_for_check
                    .notification()
                    .builder()
                    .title("Acta Ordia Signer")
                    .body("You're already on the latest version.")
                    .show();
            }
            Err(_) => {
                let _ = app_for_check
                    .notification()
                    .builder()
                    .title("Acta Ordia Signer")
                    .body("Couldn't check for updates right now — check your internet connection and try again.")
                    .show();
            }
        }
    });
}

fn main() {
    // Held for the whole process lifetime (main() blocks on tauri's .run()
    // until exit) — dropping it early would stop flushing events.
    let _sentry_guard = telemetry::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // A second launch opens the status popover instead of binding
            // the port twice. (Previously referenced a "main" window that
            // never existed — this app has never had a persistent window;
            // `"windows": []` in tauri.conf.json, dead code until now.)
            status_window::open_status_window(app);
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
        .plugin(tauri_plugin_notification::init())
        .manage(SigningState::default())
        .manage(PassphraseChannel::default())
        .manage(SignerActivity::default())
        .invoke_handler(tauri::generate_handler![
            submit_passphrase,
            cancel_passphrase,
            status_window::get_signer_status,
        ])
        .setup(|app| {
            server::spawn(app.handle().clone());

            // Default-on, user-confirmed: a signing tool should just be
            // ready. Only asserted on the actual first run — never
            // re-asserted later, so an explicit opt-out via the tray
            // checkbox sticks across restarts.
            if mark_first_run_if_new(app.handle()) {
                let _ = app.autolaunch().enable();
                let _ = app
                    .notification()
                    .builder()
                    .title("Acta Ordia Signer")
                    .body("Running in your system tray — look for the icon when you need to sign a document.")
                    .show();
            }

            // Courtesy check only — failure (offline, endpoint down) is
            // silent and never blocks startup. Notifies, doesn't auto-
            // install; installing is only ever triggered by the user via
            // the "Check for Updates" menu item below.
            let startup_updater_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(updater) = startup_updater_app.updater() {
                    if let Ok(Some(update)) = updater.check().await {
                        let _ = startup_updater_app
                            .notification()
                            .builder()
                            .title("Acta Ordia Signer update available")
                            .body(format!(
                                "Version {} is available — open the tray menu and choose \"Check for Updates\" to install it.",
                                update.version
                            ))
                            .show();
                    }
                }
            });

            let autostart_enabled = app.autolaunch().is_enabled().unwrap_or(false);
            let status_item = MenuItem::with_id(app, "status", "Status…", true, None::<&str>)?;
            let autostart_item =
                CheckMenuItem::with_id(app, "autostart", "Start at login", true, autostart_enabled, None::<&str>)?;
            let update_item = MenuItem::with_id(app, "check_updates", "Check for Updates", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit Acta Ordia Signer", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status_item, &autostart_item, &update_item, &quit_item])?;

            let autostart_item_for_toggle = autostart_item.clone();

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("Acta Ordia Signer — private key never leaves this machine")
                // Left-click opens the status popover instead of the menu
                // on platforms that support it. Unsupported on Linux (the
                // tray-icon crate never emits Click there — right-click
                // still opens the menu as normal), so the "Status…" menu
                // item above is the one path that works everywhere.
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    } = event
                    {
                        status_window::open_status_window(tray.app_handle());
                    }
                })
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "quit" => request_quit(app),
                    "status" => status_window::open_status_window(app),
                    "check_updates" => check_for_updates_now(app),
                    "autostart" => toggle_autostart(app, &autostart_item_for_toggle),
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building acta-ordia-signer")
        .run(|_app_handle, event| {
            // Tray-only app: the process must never exit just because the
            // transient passphrase window (the only window that ever opens)
            // was closed. Without this, closing that window after Unlock/Cancel
            // silently killed the whole process — HTTP server, tray, everything
            // — since Tauri's default is "exit when the last open window closes."
            // Confirmed via a real E2E smoke test: /prepare succeeded, the user
            // clicked Unlock, and the agent process vanished from `ps aux`.
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                api.prevent_exit();
            }
        });
}

#[cfg(test)]
mod regression_tests {
    //! Guards for the two 2026-07-20 E2E bugs (see acta-ordia-signer memory:
    //! passphrase window did nothing, then closing it killed the whole
    //! process). Neither bug was ever visible to `cargo build`/`cargo test`
    //! or the prior code-review-style security audit — both only surfaced
    //! by physically clicking through the app.
    //!
    //! The exit-prevention fix specifically resists a real behavioral test:
    //! `tauri::RunEvent::ExitRequested`'s fields (`api: ExitRequestApi`) are
    //! private to the `tauri` crate (confirmed by reading the vendored
    //! source, `tauri-2.11.5/src/app.rs`), so no code outside `tauri` itself
    //! can construct one to drive through our closure. `tauri::test`'s
    //! `mock_builder()` also doesn't expose a way to trigger `RunEvent`s
    //! through `.run()` — it's built for IPC command testing, not the
    //! top-level event loop. Given that, this is a source-presence guard,
    //! not a behavioral one: it fails loudly if someone reverts the fix
    //! shape, but can't prove the runtime behavior — the E2E click-through
    //! test remains the only way to prove that.

    const MAIN_RS_SOURCE: &str = include_str!("main.rs");
    const TAURI_CONF_JSON: &str = include_str!("../tauri.conf.json");

    #[test]
    fn withglobaltauri_is_enabled_in_tauri_conf() {
        // Regression guard: dist/passphrase.html calls window.__TAURI__.core,
        // which Tauri only injects when this is true. Without it, the script
        // throws before any addEventListener runs and Unlock/Cancel do
        // nothing — no error visible anywhere, exactly what was observed.
        let conf: serde_json::Value =
            serde_json::from_str(TAURI_CONF_JSON).expect("tauri.conf.json must be valid JSON");
        assert_eq!(
            conf["app"]["withGlobalTauri"],
            serde_json::Value::Bool(true),
            "app.withGlobalTauri must stay true — dist/passphrase.html depends on window.__TAURI__.core existing"
        );
    }

    #[test]
    fn passphrase_html_actually_depends_on_the_global_this_test_guards() {
        // If passphrase.html stops using window.__TAURI__ (e.g. switched to
        // an ES module import), the above test would start guarding a
        // no-longer-relevant setting — this keeps the two in sync.
        let html = include_str!("../../dist/passphrase.html");
        assert!(
            html.contains("window.__TAURI__"),
            "passphrase.html no longer uses window.__TAURI__ — the withGlobalTauri requirement (and its regression test) may no longer apply"
        );
    }

    #[test]
    fn run_closure_still_prevents_exit_on_exit_requested() {
        // Source-presence guard only (see module doc for why a behavioral
        // test isn't possible here). Fails if main() goes back to
        // `.run(tauri::generate_context!())` directly, or the match arm /
        // prevent_exit() call is removed.
        assert!(
            MAIN_RS_SOURCE.contains("RunEvent::ExitRequested"),
            "main() must still handle RunEvent::ExitRequested explicitly"
        );
        assert!(
            MAIN_RS_SOURCE.contains("api.prevent_exit()"),
            "main() must still call prevent_exit() — without it, closing the passphrase window kills the whole process"
        );
    }
}
