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

    embed_comctl32_v6_manifest_for_test_binaries();
}

/// `tauri_build::try_build` above embeds a Comctl32-v6 manifest, but scoped
/// (via `-bin=<name>`) to the main `[[bin]]` target only. `tests/*.rs`
/// integration tests compile to a SEPARATE binary that never got one —
/// which is exactly why `tests/updater_integration.rs` crashed with
/// STATUS_ENTRYPOINT_NOT_FOUND on windows-latest CI the moment it linked
/// any code (via wry/tao/the dialog plugin, pulled in by building a real
/// `tauri::test` app) that calls a Comctl32-v6-only API
/// (SetWindowSubclass/DefSubclassProc/GetWindowSubclass — these only
/// resolve by name in Comctl32 v6; without a manifest requesting it,
/// Windows loads the ancient system-default v5, which doesn't export them,
/// and the process dies at load time). Confirmed directly via dumpbin on
/// real CI artifacts: the main binary's import table showed those symbols
/// resolving fine and had an embedded manifest declaring the v6 dependency
/// (publicKeyToken 6595b64144ccf1df); the test binary had the same
/// symbols imported but NO manifest at all.
///
/// `cargo:rustc-link-arg-tests` scopes a link arg to `tests/` integration
/// test binaries specifically (as opposed to `-bin`/`-bins`, which only
/// reach `[[bin]]` targets), so this leaves the main binary's existing
/// manifest untouched.
fn embed_comctl32_v6_manifest_for_test_binaries() {
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }

    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>
"#;

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_path = std::path::Path::new(&out_dir).join("test-comctl32-v6.manifest");
    std::fs::write(&manifest_path, manifest).expect("failed to write test binary manifest");

    println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}",
        manifest_path.display()
    );
}
