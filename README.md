# Acta Ordia Signer

A lightweight native agent (Rust + Tauri) that signs ICP-Brasil PKI documents
locally. **The private key never leaves this process** — it never transits
the network, and this agent never sends it anywhere.

Open source deliberately: users are being asked to install a binary that
touches their most sensitive cryptographic material, and auditability is
part of how that trust is earned (see Doc_13 §5.1 in the main app repo).

## Status: real A1 (.p12) signing logic written and compile-verified

`/health` is real. `/prepare` and `/sign` now contain actual logic — file
picker, confirmation dialog, passphrase window, `.p12` parsing, and the raw
RSA sign — rather than a `501` stub. **`cargo build` and `cargo build
--release` both succeed cleanly** (2026-07-18, Linux, after installing the
GTK/WebKit dev headers) — see "Verified against real compiler output"
below for what that confirmed and what's still unverified (this proves the
code compiles, not that it's been run against a real ICP-Brasil cert or
tested end-to-end with the web app).

## The protocol — two round trips, not one

Earlier drafts of this repo assumed the web app could hand a session
straight to `/sign` in one call. That's wrong: the CMS digest the backend
computes depends on which certificate is used (the signer's name gets
embedded in the PDF placeholder *before* hashing — see `cms.ts`'s header in
the main repo), so the certificate has to be chosen and its public chain
revealed to the backend *before* a digest can even exist. Full flow:

1. User clicks "Sign with Certificate" in the web app.
2. Backend's `preparePkiSigningRequest` callable freezes the document,
   creates a signing session, and mints a short-lived HMAC token.
3. Web app calls this agent's `POST /prepare` with the session info. Agent:
   - opens a native file picker filtered to `.p12`/`.pfx` (**A1 first** — A3
     hardware token / PKCS#11 support is deferred, see
     `phase-2b-icp-brasil-signing-plan.md` in the main repo),
   - opens a small local window (`dist/passphrase.html`) to collect the
     certificate password — no cross-platform native password dialog
     exists, so this is a minimal webview form instead,
   - parses the `.p12` and extracts the certificate's subject (its CN, in
     ICP-Brasil's `"Name:CPF"`/`"Name:CNPJ"` format),
   - **only then** shows a single confirmation dialog — deliberately placed
     after the certificate is already known, so it can show *which identity*
     is about to sign, not just the acta title ("Acta Ordia is requesting
     your signature for *acta title*, using the certificate for: *Name:CPF*.
     Continue?" — the title is sanitized: length-capped and stripped of
     control/bidi-override characters before display),
   - stashes the unlocked private key **in memory only**, keyed by
     `session_id`, for ~15 minutes (matches the backend session TTL — see
     `src-tauri/src/state.rs`),
   - returns the **public certificate chain** plus a freshly generated
     256-bit random `agent_token` (OS CSPRNG) to the web app — the
     per-session shared secret that `/sign` will require back.
4. Web app forwards that chain to the backend's `preparePkiSignatureDigest`
   callable, which returns a pre-hashed **SHA-256 digest** — not raw
   document bytes, not the PDF — **plus an Ed25519 signature over that digest**
   (`digestSignatureBase64`), produced with a private key held only in the
   backend's Secret Manager (`PKI_DIGEST_SIGNING_PRIVATE_KEY`). (Forge's own
   signing hook on the backend only exposes an already-hashed digest — which
   happens to match the native mode of Windows `CryptSignHash`, macOS
   `SecKeyCreateSignature`, and PKCS#11's `CKM_RSA_PKCS`, so A3 tokens will use
   the identical contract later.)
5. Web app calls this agent's `POST /sign` with that digest, the backend's
   `digest_signature_base64`, **and the `agent_token` from step 3**. Before
   anything is signed or any state is consumed, the agent **verifies the
   Ed25519 signature over the digest against its embedded public key** — this
   is what proves the digest actually came from the backend. A bad, wrong, or
   missing signature → `403 invalid_digest_signature`, session left intact. It
   also checks the `agent_token` (constant-time compare; missing/wrong →
   `403 invalid_agent_token`, session left intact) as a secondary
   session-binding step. Only then does it build a DigestInfo (SHA-256 OID +
   digest), sign it with a **raw RSA PKCS1v1.5 encrypt** (not a hashing sign
   call — that would double-hash), evict the key (single-use), and return only
   the signature bytes. The Ed25519 check is the load-bearing defense: the
   Origin header only stops browser-JS CSRF and is trivially spoofable by any
   local process, and the `agent_token` alone is not enough either (an attacker
   who drives both `/prepare` and `/sign` just reads the token out of the
   `/prepare` response) — but forging a valid digest signature requires the
   backend's private key, which no local process has.
6. Web app forwards the signature bytes to the backend's
   `completePkiSignature` callable, which reconstructs the final CMS and
   embeds the PAdES-B signature into the PDF.

At no point does this agent receive or transmit the PDF, and the private
key/passphrase never leave step 3–5 of this process's own memory.

See `src-tauri/src/protocol.rs` for the current (hand-maintained, no shared
schema package yet) request/response shapes, and `src-tauri/src/state.rs`
for the in-memory session TTL.

## Development

Requires Rust (stable) + the Tauri CLI. On Linux, also requires the GTK/
WebKit dev headers (`libgtk-3-dev`, `libwebkit2gtk-4.1-dev`,
`libjavascriptcoregtk-4.1-dev`, `libsoup-3.0-dev`) and OpenSSL dev headers
(`libssl-dev`) for the `openssl` crate.

```bash
npm install
npm run dev     # cargo tauri dev — tray-only, no visible window by default
npm run build   # cargo tauri build — produces a bundled binary
```

While `npm run dev` is running:

```bash
curl http://127.0.0.1:7734/health
# {"status":"ok","version":"0.1.2"}
```

## Verified against real compiler output (2026-07-18, re-verified 2026-07-20, 2026-10-27, 2026-10-29)

`cargo build`, `cargo test` (62/62 — 58 unit tests across `main.rs`,
`passphrase.rs`, `state.rs`, `server.rs`, `protocol.rs`, `activity.rs`,
`mutex_ext.rs`, plus 4 integration tests in `tests/updater_integration.rs`),
and `cargo clippy --all-targets --
-D warnings` (zero warnings) all pass — and, since 2026-10-27, pass on
**all three target platforms** (Linux, macOS, Windows), automatically, on
every push, via `.github/workflows/test.yml` (`cargo check --release` was
also run manually at the time, but isn't one of the commands CI actually
runs). Locally
this was first verified on Linux only, after installing `libgtk-3-dev
libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev
libssl-dev`. This confirms:

- `passphrase.rs`'s use of `AppHandle::run_on_main_thread` compiles against
  the installed Tauri 2 crate version.
- `server.rs`'s `tauri-plugin-dialog` call shapes (callback-based `show` /
  `pick_file` with a bounded `recv_timeout`, `FilePath::into_path`) are
  valid.
- `build.rs` registers an app ACL manifest
  (`tauri_build::AppManifest::new().commands(...)`) so the
  `"windows": ["passphrase"]` scoping in `capabilities/default.json` is
  actually enforced by Tauri's ACL system — before 2026-07-20 that scoping
  was silently unenforced (no app manifest → the ACL branch was skipped for
  local windows).
- `icons/*` regenerated via `cargo tauri icon <source>` — real RGBA PNGs, a
  real `.icns` container (was previously a flat PNG renamed), real `.ico`.

### Security hardening pass (2026-07-20)

Applied after an adversarial audit (`SECURITY_AUDIT_2026-07-20.md`):

- **Backend Ed25519 digest signature** (finding 1, critical — the real fix):
  the backend signs the digest with an Ed25519 private key held only in Secret
  Manager (`PKI_DIGEST_SIGNING_PRIVATE_KEY`) and returns the signature to the
  browser; `/sign` verifies it against an embedded public key
  (`PKI_DIGEST_PUBLIC_KEY_HEX` in `server.rs`) **before signing or consuming
  the session**, rejecting anything else with `403 invalid_digest_signature`.
  This is what actually closes the "any local process spoofs Origin and uses
  the agent as a signature oracle" gap: forging a valid signature for an
  attacker-chosen digest requires the backend's private key, which no local
  process has. A public key is safe to ship in an open-source binary.
- **Per-session `agent_token`** (secondary, *not* load-bearing): `/prepare`
  returns a 256-bit CSPRNG token; `/sign` requires it back. This was the
  original finding-1 fix attempt, but a later red-team pass showed it does not
  actually close the oracle on its own — an attacker who drives both
  `/prepare` and `/sign` simply reads the token out of the `/prepare` response.
  It is kept as a cheap secondary session-binding convenience, but the Ed25519
  check above is the primary defense.
- **`acta_title` and the certificate's subject CN both sanitized** before
  the OS confirm dialog (and before the CN goes out in `/prepare`'s
  response): control and bidi-override/invisible characters stripped,
  length capped at 120 chars. The CN sanitization was added later
  (2026-10-28, audit finding) — a `.p12`'s CN is fully attacker-controlled
  (anyone can mint a self-signed cert with any CN string), so the
  original code's assumption that only `acta_title` needed this
  protection was wrong; the one line whose whole job is letting the user
  confirm *whose identity* is about to sign was spoofable the same way.
- **Passphrase and raw `.p12` bytes wrapped in `zeroize::Zeroizing`**
  (finding 2) — scrubbed from heap memory on drop.
- **App ACL manifest registered in `build.rs`** (finding 3, above).
- **Dev-server origin (`http://localhost:5173`) is debug-builds-only**
  (finding 4) — release builds trust only `https://app.actaordia.com`.
- **Explicit CSP** (`default-src 'self'`) on the passphrase webview instead
  of `csp: null` (finding 5).
- **Request bodies capped at 16 KB** (finding 6).
- **Confirm dialog and file picker bounded by a 5-minute timeout**
  (finding 7), matching the passphrase prompt — one abandoned dialog no
  longer wedges the single-threaded listener forever.

The web-app counterpart (`src/lib/pkiSigning.ts` +
`PkiSignaturePanel.tsx` in the main repo) forwards both the backend's
`digest_signature_base64` (from `preparePkiSignatureDigest`) and the
`agent_token` (from the `/prepare` response) into `/sign`. The backend change
is the digest-signing step in `functions/src/signing/prepare-digest.ts` — the
`agent_token` itself never transits the backend.

**Three different, easily-conflated levels of "verified" — compiling is not
the same as automated tests passing, and automated tests passing is not the
same as correct at runtime against real inputs:**

1. **Compiles** — `cargo build` succeeding only proves the code is
   well-typed against the installed crate versions. True on all 3
   platforms (both locally for Linux, and via CI for all three).
2. **Automated tests pass, in CI, on all 3 platforms** — `cargo test`'s 62
   tests (58 unit + 4 integration, see above) and `cargo clippy` run on
   every push on Linux, macOS, *and* Windows (`.github/workflows/test.yml`).
   The `tests/updater_integration.rs` suite specifically exercises
   tauri-plugin-updater's real manifest-parsing and Ed25519
   signature-verification path headlessly (no GUI) — see "What's not built
   yet" below for exactly what that does and doesn't prove. Full release
   *bundles* (AppImage/.deb/.rpm, .msi/.exe, .dmg) are also built on all 3
   platforms by `.github/workflows/release.yml` on every tagged release
   (confirmed working end-to-end as of `v0.1.2`), but that's an automated
   build succeeding, not a human running the installed app.
3. **Real functional validation — still the biggest gap:**
   - Never run against a real ICP-Brasil certificate or a real signing
     session — no proof yet that `handle_prepare`/`handle_sign` actually
     produce a signature the backend accepts.
   - No GUI click-through E2E test confirmed on macOS or Windows (one was
     done on Linux — see the E2E testing notes in project history). CI
     proves the binaries build and the headless crypto/logic tests pass
     on all 3 OSes; it does not click through the actual file picker,
     confirm dialog, or passphrase window on macOS/Windows.
   - `Cargo.lock` was generated against whatever crate versions were latest
     as of this build; hasn't been pinned/audited for a real release.
   - Locally on Linux, `cargo tauri build` (full bundle: AppImage/.deb)
     panics with "Can't detect any appindicator library" unless
     `libayatana-appindicator3-dev` is also installed (CI's runners already
     have it, and `release.yml`'s real builds — including the AppImage
     target — have succeeded there since `v0.1.2`). Only affects the local
     bundling step; `cargo build`/`cargo build --release` and `cargo tauri
     build --no-bundle` work without it.

## What's not built yet

- **A3 / PKCS#11 hardware token support** — same protocol, different local
  key source. Deferred by product decision (A1 first is more realistic for
  a first usable release; A3 brings far more driver/OS/support complexity).
- **Deep-link protocol handler** (`actaordia-signer://`) — only the
  localhost HTTP fallback exists so far.
- **Signed binary distribution** (Apple Developer ID / Windows EV
  certificate) — a deliberate, accepted tradeoff for now, not an oversight.
  Builds are unsigned at the OS level (Gatekeeper/SmartScreen will show an
  "unknown publisher" warning on first install); the update *channel*
  itself is still cryptographically verified regardless — see "Trust
  model" below.
- **Automated OS-level install → update test in CI** — `tests/updater_integration.rs`
  now runs tauri-plugin-updater's real manifest-parsing and Ed25519
  signature-verification path on every `cargo test` run (headless, no GUI,
  no real window — see `tauri::test::mock_app`), and specifically proves a
  tampered artifact or a release signed by the wrong key is rejected, not
  silently installed. What it still doesn't cover: the actual OS-level
  binary swap (`Update::install`) — that's been verified manually once (see
  Trust model below) but isn't automated, since doing so would mean
  installing real binaries and restarting a process inside a CI job, which
  is a materially different (and much more OS-specific) problem than the
  crypto path.

## Trust model

- The agent's signing traffic is local-only (`127.0.0.1`) — the document,
  the private key, and the passphrase never transit the network. The origin
  allowlist stops browser-JS CSRF only; protection against other local
  processes comes from verifying the backend's Ed25519 signature over the
  digest against the agent's embedded public key before signing (the
  per-session `agent_token` is only a secondary session-binding check, not
  the primary defense — see the security hardening notes above).
- The agent does send crash/error telemetry to a dedicated Sentry project
  (`src-tauri/src/telemetry.rs`) — deliberately narrow: only static,
  whitelisted error *codes* (e.g. `"invalid_certificate"`), never the error
  message text, the passphrase, `.p12`/certificate bytes, or the acta title.
  `send_default_pii` is off. This is disclosed here because "does not phone
  home" would otherwise overstate what the agent does.
- It signs only backend-issued Acta Ordia signing sessions — it is not a
  generic document signer for arbitrary input.
- The private key is held in memory only, for a short TTL, single-use, and
  is never written to disk or logged.
- Source is open — enterprise customers can audit or build from source.
- **Update-channel integrity is separate from, and does not depend on, OS
  code signing.** Every release is signed with a dedicated Tauri
  updater keypair (`TAURI_SIGNING_PRIVATE_KEY`, a GitHub Secret, never
  committed); the app verifies that signature against its embedded public
  key (`tauri.conf.json`'s `plugins.updater.pubkey`) before installing an
  update. A tampered or substituted update fails that check and is
  refused, independent of whether the binary itself carries an OS-trusted
  publisher signature.
