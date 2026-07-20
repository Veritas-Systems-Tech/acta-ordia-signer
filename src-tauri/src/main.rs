// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod passphrase;
mod protocol;
mod server;
mod state;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

use passphrase::{cancel_passphrase, submit_passphrase, PassphraseChannel};
use state::SigningState;

fn main() {
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
