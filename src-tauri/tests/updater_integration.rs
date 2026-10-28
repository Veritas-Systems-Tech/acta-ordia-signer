//! TEMPORARY bisection stage 2: does building a bare headless
//! tauri::test::MockRuntime app (no updater plugin at all) trigger the
//! Windows STATUS_ENTRYPOINT_NOT_FOUND crash by itself?

#[test]
fn builds_bare_mock_app() {
    let _app = tauri::test::mock_builder()
        .build(tauri::generate_context!())
        .expect("failed to build mock Tauri app");
}
