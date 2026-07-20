fn main() {
    // Register an app ACL manifest so the `"windows": ["passphrase"]`
    // scoping in capabilities/default.json is actually enforced by Tauri's
    // ACL system. Without this, no app-level manifest is generated and the
    // ACL branch in Tauri's IPC resolution is skipped entirely for local
    // windows — the capability file would be pure documentation (security
    // audit 2026-07-20, finding 3).
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&["submit_passphrase", "cancel_passphrase"]),
        ),
    )
    .expect("failed to run tauri-build");
}
