//! Exercises the real update-channel crypto path (tauri-plugin-updater's
//! manifest parsing + Ed25519 signature verification against the embedded
//! pubkey) end-to-end, without needing a real OS install or a GUI.
//!
//! A manual install -> publish-new-version -> verify-client-updates pass has
//! been done once by hand (see README's Trust model section), but nothing
//! automated covered a regression in that path until this test. It does not
//! prove the OS-level binary swap (`Update::install`) works — that's a
//! separate, much more OS-specific concern and genuinely needs either
//! another manual pass or a real GUI E2E test — but it does prove that a
//! tampered manifest or artifact is rejected and a correctly signed one is
//! accepted, which is the actual security property Codex's review was
//! questioning.
//!
//! Runs against `tauri::test::mock_app()` (a headless `MockRuntime`, no
//! window, no webview) so it's safe and fast in CI on every platform in the
//! test matrix.

use std::sync::{Arc, Mutex};

use base64::Engine;
use tauri_plugin_updater::UpdaterExt;
use tiny_http::{Header, Response, Server};

/// A throwaway minisign keypair generated fresh for this test run. Never the
/// real `TAURI_SIGNING_PRIVATE_KEY` — this never signs anything that leaves
/// the test process.
struct TestKeyPair {
    inner: minisign::KeyPair,
}

impl TestKeyPair {
    fn generate() -> Self {
        Self {
            inner: minisign::KeyPair::generate_unencrypted_keypair()
                .expect("failed to generate test minisign keypair"),
        }
    }

    /// Same shape as `tauri.conf.json`'s `plugins.updater.pubkey` field.
    fn pubkey_b64(&self) -> String {
        let pk_box_text = self.inner.pk.to_box().unwrap().into_string();
        base64::engine::general_purpose::STANDARD.encode(pk_box_text)
    }

    /// Same shape as a release manifest's `platforms.<target>.signature` field.
    fn sign_b64(&self, data: &[u8]) -> String {
        let sig_box = minisign::sign(
            Some(&self.inner.pk),
            &self.inner.sk,
            data,
            Some("test fixture — never a real release"),
            None,
        )
        .expect("failed to sign test fixture");
        base64::engine::general_purpose::STANDARD.encode(sig_box.into_string())
    }
}

/// A local stand-in for the real update bucket (`gs://acta-ordia-signer-downloads`):
/// serves whatever manifest/artifact bytes are currently set at
/// `/latest.json` and `/artifact`. Content can be swapped after the server
/// is already listening, which is what lets tests embed the server's own
/// (only-known-after-bind) port inside the manifest's `url` field.
struct MockUpdateServer {
    port: u16,
    manifest: Arc<Mutex<String>>,
    artifact: Arc<Mutex<Vec<u8>>>,
}

impl MockUpdateServer {
    fn start() -> Self {
        let server = Server::http("127.0.0.1:0").expect("failed to bind local test HTTP server");
        let port = server.server_addr().to_ip().unwrap().port();
        let manifest = Arc::new(Mutex::new(String::new()));
        let artifact = Arc::new(Mutex::new(Vec::new()));

        let manifest_for_thread = manifest.clone();
        let artifact_for_thread = artifact.clone();
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let url = request.url().to_string();
                if url == "/latest.json" {
                    let body = manifest_for_thread.lock().unwrap().clone();
                    let header =
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                    let response = Response::from_string(body)
                        .with_header(header)
                        .with_status_code(200);
                    let _ = request.respond(response);
                } else if url == "/artifact" {
                    let body = artifact_for_thread.lock().unwrap().clone();
                    let response = Response::from_data(body).with_status_code(200);
                    let _ = request.respond(response);
                } else {
                    let response = Response::from_string("not found").with_status_code(404);
                    let _ = request.respond(response);
                }
            }
        });

        Self {
            port,
            manifest,
            artifact,
        }
    }

    fn latest_json_url(&self) -> String {
        format!("http://127.0.0.1:{}/latest.json", self.port)
    }

    fn artifact_url(&self) -> String {
        format!("http://127.0.0.1:{}/artifact", self.port)
    }

    /// Publishes a release manifest + its artifact bytes, matching the real
    /// schema tauri-plugin-updater expects and the real `release.yml`
    /// publish job produces (one `platforms.<target>` entry per OS/arch).
    fn publish(&self, version: &str, signature_b64: &str, artifact_bytes: Vec<u8>) {
        let target = tauri_plugin_updater::target().expect("unsupported test platform");
        let manifest_json = serde_json::json!({
            "version": version,
            "notes": "test fixture",
            "pub_date": "2026-01-01T00:00:00Z",
            "platforms": {
                target: {
                    "signature": signature_b64,
                    "url": self.artifact_url(),
                }
            }
        })
        .to_string();

        *self.manifest.lock().unwrap() = manifest_json;
        *self.artifact.lock().unwrap() = artifact_bytes;
    }
}

/// Builds a headless app (`MockRuntime` — no real window/webview) using the
/// project's REAL `tauri.conf.json`, not a bare mock context: the updater
/// plugin's config deserialization requires a `plugins.updater` block to
/// exist at all (`tauri::test::mock_context`'s config has none, which fails
/// setup outright). Using the real config means the plugin boots with the
/// real production pubkey — harmless, since every test below immediately
/// overrides it via `UpdaterBuilder::pubkey()` with a throwaway test key
/// before calling `.build()`.
fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
    tauri::test::mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(tauri::generate_context!())
        .expect("failed to build mock Tauri app")
}

fn updater_for(
    server: &MockUpdateServer,
    pubkey_b64: String,
) -> tauri_plugin_updater::Updater {
    mock_app()
        .updater_builder()
        .endpoints(vec![server.latest_json_url().parse().unwrap()])
        .unwrap()
        .pubkey(pubkey_b64)
        .build()
        .expect("failed to build updater")
}

#[test]
fn check_finds_a_correctly_signed_newer_release() {
    let keys = TestKeyPair::generate();
    let artifact_bytes = b"fake update artifact contents".to_vec();
    let signature_b64 = keys.sign_b64(&artifact_bytes);

    let server = MockUpdateServer::start();
    server.publish("99.0.0", &signature_b64, artifact_bytes.clone());

    let updater = updater_for(&server, keys.pubkey_b64());

    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check() failed")
        .expect("expected an update to be available");
    assert_eq!(update.version, "99.0.0");

    let downloaded = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}))
        .expect("download() should succeed with a correctly signed artifact");
    assert_eq!(downloaded, artifact_bytes);
}

#[test]
fn check_reports_no_update_when_remote_version_is_not_newer() {
    let keys = TestKeyPair::generate();
    let artifact_bytes = b"irrelevant for this test".to_vec();
    let signature_b64 = keys.sign_b64(&artifact_bytes);

    let server = MockUpdateServer::start();
    // The app's real current version (from tauri.conf.json, kept in sync
    // with Cargo.toml's package version) — an equal remote version must
    // not be treated as an available update.
    server.publish(env!("CARGO_PKG_VERSION"), &signature_b64, artifact_bytes);

    let updater = updater_for(&server, keys.pubkey_b64());

    let update = tauri::async_runtime::block_on(updater.check()).expect("check() failed");
    assert!(
        update.is_none(),
        "a same-or-older remote version must not be reported as an available update"
    );
}

#[test]
fn download_rejects_a_tampered_artifact() {
    let keys = TestKeyPair::generate();
    let real_artifact = b"the genuine update payload".to_vec();
    // Sign the REAL bytes, but serve DIFFERENT bytes — simulates a
    // man-in-the-middle or a compromised storage bucket swapping the
    // binary after it was already signed.
    let signature_b64 = keys.sign_b64(&real_artifact);
    let tampered_artifact = b"a maliciously substituted payload!!".to_vec();

    let server = MockUpdateServer::start();
    server.publish("99.0.0", &signature_b64, tampered_artifact);

    let updater = updater_for(&server, keys.pubkey_b64());

    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check() failed")
        .expect("manifest parses fine even though the artifact is tampered");

    let result = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}));
    assert!(
        result.is_err(),
        "a tampered artifact must fail signature verification, not silently install"
    );
}

#[test]
fn download_rejects_a_release_signed_by_the_wrong_key() {
    let real_keys = TestKeyPair::generate();
    let attacker_keys = TestKeyPair::generate();
    let artifact_bytes = b"looks legitimate, signed by the wrong key".to_vec();
    // Signed by a DIFFERENT keypair than the one the client trusts —
    // simulates an attacker who controls the storage bucket but not the
    // real TAURI_SIGNING_PRIVATE_KEY.
    let signature_b64 = attacker_keys.sign_b64(&artifact_bytes);

    let server = MockUpdateServer::start();
    server.publish("99.0.0", &signature_b64, artifact_bytes);

    let updater = updater_for(&server, real_keys.pubkey_b64());

    let update = tauri::async_runtime::block_on(updater.check())
        .expect("check() failed")
        .expect("manifest parses fine even though it's signed by the wrong key");

    let result = tauri::async_runtime::block_on(update.download(|_, _| {}, || {}));
    assert!(
        result.is_err(),
        "a release signed by a key other than the embedded pubkey must be rejected"
    );
}
