// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod passphrase;
mod protocol;
mod server;
mod state;
mod telemetry;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

use passphrase::{cancel_passphrase, submit_passphrase, PassphraseChannel};
use state::SigningState;

fn main() {
    // Held for the whole process lifetime (main() blocks on tauri's .run()
    // until exit) — dropping it early would stop flushing events.
    let _sentry_guard = telemetry::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // A second launch focuses/no-ops instead of binding the port twice.
            let _ = app
                .get_webview_window("main")
                .map(|w| {
                    let _ = w.show();
                    let _ = w.set_focus();
                });
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .manage(SigningState::default())
        .manage(PassphraseChannel::default())
        .invoke_handler(tauri::generate_handler![submit_passphrase, cancel_passphrase])
        .setup(|app| {
            server::spawn(app.handle().clone());

            let quit_item = MenuItem::with_id(app, "quit", "Quit Acta Ordia Signer", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&quit_item])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("Acta Ordia Signer — private key never leaves this machine")
                .on_menu_event(|app, event| {
                    if event.id.as_ref() == "quit" {
                        app.exit(0);
                    }
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
