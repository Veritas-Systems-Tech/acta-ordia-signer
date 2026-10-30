//! Remembers the last `.p12`/`.pfx` path the user picked, so the file
//! picker opens pre-seeded there instead of making the user re-browse to
//! the same certificate on every single signature. Not a certificate
//! store, not detection — just a convenience for the one file users
//! actually keep re-selecting (per the audit finding this fixes).
//!
//! Stored as a single plain-text file (the path, nothing else) in Tauri's
//! app-local-data directory. Deliberately NOT the certificate's contents
//! or passphrase — just where to point the OS picker next time. Read
//! failures (file doesn't exist yet, directory not created yet) are
//! treated as "no memory," never as an error worth surfacing.

use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

const FILE_NAME: &str = "last_certificate_path.txt";

fn memory_file_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_local_data_dir().ok().map(|dir| dir.join(FILE_NAME))
}

/// The remembered path, if any, and if the file it points to still exists —
/// a stale path to a deleted/moved file would otherwise pre-seed the picker
/// somewhere useless.
pub fn last_certificate_dir(app: &AppHandle) -> Option<PathBuf> {
    let path = memory_file_path(app)?;
    let remembered = std::fs::read_to_string(path).ok()?;
    let remembered_path = PathBuf::from(remembered.trim());
    if remembered_path.exists() {
        remembered_path.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

/// Best-effort — a failure to persist this is not worth surfacing to the
/// user; it just means the picker won't be pre-seeded next time.
pub fn remember_certificate_path(app: &AppHandle, picked_path: &Path) {
    let Some(memory_path) = memory_file_path(app) else { return };
    if let Some(dir) = memory_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(memory_path, picked_path.to_string_lossy().as_bytes());
}
