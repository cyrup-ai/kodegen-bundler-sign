//! API key file management for CI/CD environments

use crate::error::{Result, SetupError};

/// Write .p8 API key file from environment to standard location
///
/// Checks for `APPLE_API_KEY_CONTENT` environment variable and writes it to
/// `~/.private_keys/AuthKey_{KEY_ID}.p8`.
///
/// This enables CI/CD environments to provide the .p8 file contents as a
/// secret instead of requiring a file path.
///
/// # Returns
/// * `Ok(Some(PathBuf))` - File written successfully, returns path to the file
/// * `Ok(None)` - Env var not set, no action taken
/// * `Err(SetupError)` - Failed to write file
pub async fn ensure_api_key_file() -> Result<Option<std::path::PathBuf>> {
    if let (Ok(key_id), Ok(key_content)) = (
        std::env::var("APPLE_API_KEY"),
        std::env::var("APPLE_API_KEY_CONTENT"),
    ) {
        let key_dir = dirs::home_dir()
            .ok_or_else(|| SetupError::MissingConfig("HOME not set".to_string()))?
            .join(".private_keys");

        tokio::fs::create_dir_all(&key_dir).await?;

        let key_path = key_dir.join(format!("AuthKey_{key_id}.p8"));
        tokio::fs::write(&key_path, &key_content).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).await?;
        }

        println!("✓ Wrote API key to {}", key_path.display());
        return Ok(Some(key_path));
    }
    Ok(None)
}
