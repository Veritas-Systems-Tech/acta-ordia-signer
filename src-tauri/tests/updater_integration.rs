//! TEMPORARY bisection stage 1: does just building a headless
//! tauri::test::MockRuntime app (with the updater plugin attached, no
//! actual network/updater calls) trigger the Windows
//! STATUS_ENTRYPOINT_NOT_FOUND crash by itself?

#[test]
fn builds_mock_app_with_updater_plugin() {
    let _app = tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(tauri::generate_context!())
        .expect("failed to build mock Tauri app");
}
