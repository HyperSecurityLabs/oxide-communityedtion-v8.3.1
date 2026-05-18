// ── OXIDE encrypted SQLite database loader ─────────────────────────────
//  Loads the cgi_database/oxide_tests.db.enc file, XOR-decrypts it to memory,
//  opens with rusqlite, and returns all test records.

use anyhow::{Result, anyhow};
use std::io::Write;
use std::path::Path;

/// Database directory name — change here to relocate the test database folder
pub const DB_DIR: &str = "cgi_database";

/// Database filename (plain SQLite before encryption)
pub const DB_FILE: &str = "oxide_tests.db";

/// Encrypted database filename
pub const DB_ENC_FILE: &str = "oxide_tests.db.enc";

/// XOR key — must match tools/build_db.py DEFAULT_KEY
const XOR_KEY: &[u8] = b"OXIDE::v8.3.1::HyperSecurityOffensiveLabs";

/// Decrypt an XOR-encrypted file to a temporary path and return the path.
/// The caller should clean up the temp file after use.
pub fn decrypt_to_temp(enc_path: &Path) -> Result<std::path::PathBuf> {
    let encrypted = std::fs::read(enc_path)
        .map_err(|e| anyhow!("Failed to read encrypted DB '{}': {}", enc_path.display(), e))?;

    let decrypted: Vec<u8> = encrypted.iter()
        .enumerate()
        .map(|(i, &b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();

    // Verify it looks like a valid SQLite header
    if decrypted.len() < 16 || &decrypted[..16] != b"SQLite format 3\x00" {
        return Err(anyhow!("Decrypted data is not a valid SQLite database — wrong XOR key or corrupt file"));
    }

    let tmp = std::env::temp_dir().join(format!("oxide_tests_{}.db", std::process::id()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&decrypted)?;
    f.sync_all()?;
    Ok(tmp)
}

/// Load all test records from the encrypted SQLite database.
/// Returns a Vec of (path, method, expected_status_str, content_indicators_str,
/// severity_str, category_str, title, description, remediation, download_flag).
pub fn load_all_rows(db_path: &Path) -> Result<Vec<(String, String, String, String, String, String, String, String, String, bool)>> {
    let conn = rusqlite::Connection::open(db_path)?;

    let mut stmt = conn.prepare(
        "SELECT path, method, expected_status, content_indicators,
                severity, category, title, description, remediation, download_flag
         FROM tests ORDER BY id"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, i32>(9)? != 0,
        ))
    })?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }
    Ok(results)
}

/// Convenience: decrypt + load all rows in one call.
/// The temp file is cleaned up after loading.
pub fn decrypt_and_load(enc_path: &Path) -> Result<Vec<(String, String, String, String, String, String, String, String, String, bool)>> {
    let tmp = decrypt_to_temp(enc_path)?;
    let result = load_all_rows(&tmp);
    let _ = std::fs::remove_file(&tmp);
    result
}
