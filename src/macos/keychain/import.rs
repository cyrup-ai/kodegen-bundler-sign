//! Certificate import operations for macOS keychain

use crate::error::{Result, SetupError};
use crate::success;
use fs4::tokio::AsyncFileExt;
use rand::Rng;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use termcolor::WriteColor;
use zeroize::Zeroize;

/// Import a p12 file into keychain with exclusive locking to prevent race conditions
///
/// This function provides two layers of protection:
/// 1. Exclusive file lock prevents concurrent kodegen instances from importing simultaneously
/// 2. Check-before-import prevents duplicate certificates
///
/// # Arguments
/// * `p12_path` - Path to the temporary p12 file to import
/// * `keychain` - Name of the keychain (e.g., "login.keychain-db")
/// * `password` - Password protecting the p12 file
/// * `common_name` - Common name of the certificate (used for duplicate checking)
///
/// # Returns
/// * `Ok(())` - Import succeeded or certificate already exists
/// * `Err(SetupError)` - Import failed
///
/// # Lock Behavior
/// - Blocks if another kodegen instance is currently importing
/// - Automatically releases lock when function returns (lock file dropped)
/// - Lock file location: ~/.cache/kodegen/keychain.lock
pub async fn import_p12_with_lock(
    p12_path: &Path,
    keychain: &str,
    password: &str,
    common_name: &str,
) -> Result<()> {
    // Create lock file path in cache directory
    let lock_dir = dirs::cache_dir()
        .ok_or_else(|| {
            SetupError::MissingConfig("Could not determine cache directory".to_string())
        })?
        .join("kodegen");

    // Ensure lock directory exists
    tokio::fs::create_dir_all(&lock_dir).await.map_err(SetupError::Io)?;

    let lock_path = lock_dir.join("keychain.lock");

    // Open/create lock file
    let lock_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .await
        .map_err(SetupError::Io)?;

    // Acquire exclusive lock - fs4 tokio integration
    // This serializes all keychain imports across all kodegen process instances
    lock_file.lock_exclusive().map_err(|e| {
        SetupError::KeychainOperation(format!("Failed to acquire keychain lock: {e}"))
    })?;

    // Lock acquired - now safely check and import

    // Layer 2: Check if certificate already exists
    let check_output = tokio::process::Command::new("security")
        .args(["find-certificate", "-c", common_name, keychain])
        .output()
        .await
        .map_err(|e| {
            SetupError::CommandExecution(format!("Failed to check existing certificate: {e}"))
        })?;

    if check_output.status.success() {
        // Certificate already exists - skip import
        success!("Certificate already exists in keychain, skipping import");

        // Lock automatically released when lock_file is dropped
        return Ok(());
    }

    // Certificate doesn't exist - proceed with import
    let import_output = tokio::process::Command::new("security")
        .args([
            "import",
            p12_path
                .to_str()
                .ok_or_else(|| SetupError::InvalidConfig("Invalid p12 path".to_string()))?,
            "-k",
            keychain,
            "-P",
            password,
            "-T",
            "/usr/bin/codesign",
        ])
        .output()
        .await
        .map_err(|e| {
            SetupError::KeychainOperation(format!("Failed to execute security import: {e}"))
        })?;

    if !import_output.status.success() {
        let stderr = String::from_utf8_lossy(&import_output.stderr);
        return Err(SetupError::KeychainOperation(format!(
            "Keychain import failed: {stderr}"
        )));
    }

    // Import successful
    // Lock automatically released when lock_file is dropped at function exit

    Ok(())
}

/// Import certificate and private key into macOS keychain
///
/// Creates temporary p12 bundle and imports via `security` command.
/// Temporary files are automatically cleaned up.
pub async fn import_certificate_to_keychain(
    cert_der: &[u8],
    private_key_pem: &str,
    keychain: &str,
    common_name: &str,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Create secure temporary directory with 0700 permissions
    let temp_dir = TempDir::new()?;

    // Write certificate
    let temp_cert = temp_dir.path().join("cert.der");
    tokio::fs::write(&temp_cert, cert_der).await?;
    tokio::fs::set_permissions(&temp_cert, std::fs::Permissions::from_mode(0o600)).await?;

    // Write private key
    let temp_key = temp_dir.path().join("key.pem");
    tokio::fs::write(&temp_key, private_key_pem).await?;
    tokio::fs::set_permissions(&temp_key, std::fs::Permissions::from_mode(0o600)).await?;

    // Create p12 bundle
    let temp_p12 = temp_dir.path().join("cert.p12");

    // Generate random password for p12
    let mut password: String = (0..32)
        .map(|_| {
            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            let idx = rand::rng().random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    let output = tokio::process::Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-inkey",
            temp_key
                .to_str()
                .ok_or_else(|| SetupError::InvalidConfig("Invalid temp key path".to_string()))?,
            "-in",
            temp_cert
                .to_str()
                .ok_or_else(|| SetupError::InvalidConfig("Invalid temp cert path".to_string()))?,
            "-out",
            temp_p12
                .to_str()
                .ok_or_else(|| SetupError::InvalidConfig("Invalid temp p12 path".to_string()))?,
            "-passout",
            &format!("pass:{password}"),
        ])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SetupError::MissingDependency(
                    "openssl command not found. Please install OpenSSL.".to_string(),
                )
            } else {
                SetupError::CommandExecution(format!("Failed to create p12: {e}"))
            }
        })?;

    if !output.status.success() {
        password.zeroize();
        return Err(SetupError::CertificateGeneration(format!(
            "Failed to create p12: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    tokio::fs::set_permissions(&temp_p12, std::fs::Permissions::from_mode(0o600)).await?;

    // Import p12 to keychain using locking mechanism to prevent race conditions
    let result = import_p12_with_lock(&temp_p12, keychain, &password, common_name).await;

    // Zeroize password before checking result
    password.zeroize();

    // Return result (propagate any errors)
    result?;

    // Automatic cleanup when temp_dir is dropped
    Ok(())
}
