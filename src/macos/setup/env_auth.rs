//! CI/CD authentication from environment variables

use crate::error::{Result, SetupError};
use crate::success;
use std::io::Write;
use termcolor::WriteColor;
use super::super::keychain::TempKeychain;

/// Authentication from environment variables (CI/CD)
pub enum EnvAuth {
    Certificate {
        cert_base64: String,
        password: String,
    },
    ApiKey {
        key_id: String,
        issuer_id: String,
        key_path: std::path::PathBuf,
    },
}

/// Try to load authentication from environment variables
///
/// Priority order:
/// 1. `APPLE_CERTIFICATE` + `APPLE_CERTIFICATE_PASSWORD` (base64 .p12)
/// 2. `APPLE_API_KEY` + `APPLE_API_ISSUER` + `APPLE_API_KEY_PATH`
pub fn try_auth_from_env() -> Option<EnvAuth> {
    // Priority 1: Certificate (most common in CI/CD)
    if let (Ok(cert_b64), Ok(password)) = (
        std::env::var("APPLE_CERTIFICATE"),
        std::env::var("APPLE_CERTIFICATE_PASSWORD"),
    ) {
        return Some(EnvAuth::Certificate {
            cert_base64: cert_b64,
            password,
        });
    }

    // Priority 2: API key
    if let (Ok(key_id), Ok(issuer)) = (
        std::env::var("APPLE_API_KEY"),
        std::env::var("APPLE_API_ISSUER"),
    ) {
        // Explicit path
        if let Ok(key_path) = std::env::var("APPLE_API_KEY_PATH") {
            return Some(EnvAuth::ApiKey {
                key_id,
                issuer_id: issuer,
                key_path: key_path.into(),
            });
        }

        // Auto-search standard locations
        if let Some(key_path) = find_p8_key_in_standard_locations(&key_id) {
            return Some(EnvAuth::ApiKey {
                key_id,
                issuer_id: issuer,
                key_path,
            });
        }
    }

    None
}

/// Setup using certificate from environment (CI/CD)
pub async fn setup_with_certificate(
    cert_base64: &str,
    password: &str,
    dry_run: bool,
) -> Result<TempKeychain> {
    if dry_run {
        success!("DRY RUN: Would import certificate from APPLE_CERTIFICATE env var");
        return Err(SetupError::InvalidConfig(
            "Cannot create temp keychain in dry-run mode".to_string(),
        ));
    }

    println!("📦 Importing certificate from environment variable...");

    // Decode base64 certificate
    use base64::Engine;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(cert_base64)
        .map_err(|e| {
            SetupError::InvalidConfig(format!("Invalid APPLE_CERTIFICATE (not valid base64): {e}"))
        })?;

    // Create temporary keychain
    let temp_keychain = TempKeychain::from_certificate_bytes(&cert_bytes, password).await?;

    success!("Certificate imported to temporary keychain");
    println!("  Identity: {}", temp_keychain.signing_identity());
    println!("  Path: {}", temp_keychain.path().display());

    Ok(temp_keychain)
}

fn find_p8_key_in_standard_locations(key_id: &str) -> Option<std::path::PathBuf> {
    let filename = format!("AuthKey_{key_id}.p8");

    let mut search_paths = vec![std::path::PathBuf::from("./private_keys")];

    if let Some(home) = dirs::home_dir() {
        search_paths.push(home.join("private_keys"));
        search_paths.push(home.join(".private_keys"));
        search_paths.push(home.join(".appstoreconnect/private_keys"));
    }

    for dir in search_paths {
        let key_path = dir.join(&filename);
        if key_path.exists() && key_path.is_file() {
            println!("✓ Found API key: {}", key_path.display());
            return Some(key_path);
        }
    }

    None
}
