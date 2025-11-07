//! Temporary keychain management for CI/CD environments

use crate::error::{Result, SetupError};
use rand::distr::{Alphanumeric, SampleString};
use std::path::Path;

/// Temporary keychain that auto-deletes when dropped
///
/// Used in CI/CD to avoid polluting the login keychain.
/// Creates random-named keychain, imports certificate, auto-cleanup on drop.
///
/// # Example
/// ```no_run
/// let temp = TempKeychain::from_certificate_file("cert.p12", "password")?;
/// // Use temp.signing_identity() for signing
/// // Keychain auto-deleted when temp goes out of scope
/// ```
pub struct TempKeychain {
    path: std::path::PathBuf,
    _password: String, // Kept for lifetime, not accessed after creation
    signing_identity: String,
}

impl TempKeychain {
    /// Create from .p12 certificate file
    pub async fn from_certificate_file(cert_path: &Path, cert_password: &str) -> Result<Self> {
        let cert_bytes = tokio::fs::read(cert_path).await?;
        Self::from_certificate_bytes(&cert_bytes, cert_password).await
    }

    /// Create from certificate bytes (for base64-decoded env var)
    pub async fn from_certificate_bytes(cert_bytes: &[u8], cert_password: &str) -> Result<Self> {
        // Generate random keychain name (16 char alphanumeric)
        let keychain_name = format!(
            "{}.keychain-db",
            Alphanumeric.sample_string(&mut rand::rng(), 16)
        );

        let keychain_path = dirs::home_dir()
            .ok_or_else(|| SetupError::MissingConfig("HOME not set".to_string()))?
            .join("Library/Keychains")
            .join(&keychain_name);

        // Generate random keychain password
        let keychain_password = Alphanumeric.sample_string(&mut rand::rng(), 16);

        // Write certificate to temporary file
        let temp_dir = tempfile::TempDir::new()?;
        let temp_cert = temp_dir.path().join("cert.p12");
        tokio::fs::write(&temp_cert, cert_bytes).await?;

        // Create keychain
        run_security(
            &["create-keychain", "-p", &keychain_password],
            &keychain_path,
        ).await?;

        // Unlock keychain
        run_security(
            &["unlock-keychain", "-p", &keychain_password],
            &keychain_path,
        ).await?;

        // Import Apple's Developer ID G2 CA certificate first (required for trust chain)
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| SetupError::KeychainOperation(
                format!("Failed to create HTTP client: {}", e)
            ))?;

        let ca_cert_bytes = client
            .get("https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SetupError::KeychainOperation(format!(
                        "CA certificate download timed out after 60 seconds. Check network connection."
                    ))
                } else if e.is_connect() {
                    SetupError::KeychainOperation(
                        "Could not connect to Apple servers. Check network/firewall.".to_string()
                    )
                } else {
                    SetupError::KeychainOperation(format!("CA certificate download failed: {}", e))
                }
            })?
            .error_for_status()
            .map_err(|e| SetupError::KeychainOperation(
                format!("CA certificate HTTP {}: {}", 
                    e.status().map(|s| s.as_u16().to_string()).unwrap_or_else(|| "unknown".to_string()), e)
            ))?
            .bytes()
            .await
            .map_err(|e| SetupError::KeychainOperation(
                format!("Failed to read CA certificate bytes: {}", e)
            ))?;

        if ca_cert_bytes.is_empty() {
            return Err(SetupError::KeychainOperation(
                "CA certificate download returned empty data".to_string(),
            ));
        }

        // Write CA certificate to temp file
        let temp_ca = temp_dir.path().join("g2_ca.cer");
        tokio::fs::write(&temp_ca, &ca_cert_bytes).await?;

        // Import CA certificate from file
        let ca_import = tokio::process::Command::new("security")
            .arg("import")
            .arg(&temp_ca)
            .args(["-k", &keychain_path.to_string_lossy(), "-A"])
            .output()
            .await
            .map_err(|e| {
                SetupError::KeychainOperation(format!("Failed to execute CA certificate import: {}", e))
            })?;

        if !ca_import.status.success() {
            return Err(SetupError::KeychainOperation(format!(
                "CA certificate import failed: {}",
                String::from_utf8_lossy(&ca_import.stderr)
            )));
        }

        // Import certificate
        let import_result = tokio::process::Command::new("security")
            .arg("import")
            .arg(&temp_cert)
            .args(["-P", cert_password])
            .args([
                "-T",
                "/usr/bin/codesign",
                "-T",
                "/usr/bin/pkgbuild",
                "-T",
                "/usr/bin/productbuild",
            ])
            .arg("-k")
            .arg(&keychain_path)
            .output()
            .await;

        // Clean up temp cert
        drop(temp_dir);

        let import_output = import_result?;
        if !import_output.status.success() {
            // Clean up keychain on failure
            let _ = tokio::process::Command::new("security")
                .arg("delete-keychain")
                .arg(&keychain_path)
                .output()
                .await;

            return Err(SetupError::KeychainOperation(format!(
                "Failed to import certificate: {}",
                String::from_utf8_lossy(&import_output.stderr)
            )));
        }

        // Set keychain settings (1 hour timeout, auto-unlock)
        run_security(
            &["set-keychain-settings", "-t", "3600", "-u"],
            &keychain_path,
        ).await?;

        // Set partition list (prevents password prompts during signing)
        run_security(
            &[
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
                "-s",
                "-k",
                &keychain_password,
            ],
            &keychain_path,
        ).await?;

        // Add to keychain search list
        let list_output = tokio::process::Command::new("security")
            .args(["list-keychain", "-d", "user"])
            .output()
            .await?;

        let current_keychains = String::from_utf8_lossy(&list_output.stdout);
        let mut keychains: Vec<String> = current_keychains
            .lines()
            .map(|l| l.trim().trim_matches('"').to_string())
            .filter(|l| !l.is_empty())
            .collect();

        keychains.push(keychain_path.to_string_lossy().to_string());

        tokio::process::Command::new("security")
            .args(["list-keychain", "-d", "user", "-s"])
            .args(&keychains)
            .output()
            .await?;

        // Find signing identity
        let signing_identity = Self::find_signing_identity(&keychain_path).await?;

        Ok(Self {
            path: keychain_path,
            _password: keychain_password,
            signing_identity,
        })
    }

    async fn find_signing_identity(keychain_path: &Path) -> Result<String> {
        let output = tokio::process::Command::new("security")
            .args(["find-identity", "-v", "-p", "codesigning"])
            .arg(keychain_path)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Find Developer ID certificate
        for line in stdout.lines() {
            if (line.contains("\"Developer ID Application:")
                || line.contains("\"Apple Development:")
                || line.contains("\"Mac Developer:"))
                && let Some(start) = line.find('"')
                && let Some(end) = line[start + 1..].find('"')
            {
                return Ok(line[start + 1..start + 1 + end].to_string());
            }
        }

        Err(SetupError::KeychainOperation(
            "No valid signing identity found in temporary keychain".to_string(),
        ))
    }

    #[must_use]
    pub fn signing_identity(&self) -> &str {
        &self.signing_identity
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly cleanup the temporary keychain (async-safe)
    /// 
    /// Call this method to ensure proper cleanup in async contexts.
    /// The Drop implementation provides best-effort cleanup but may
    /// not complete before the runtime shuts down.
    pub async fn cleanup(self) -> Result<()> {
        let output = tokio::process::Command::new("security")
            .arg("delete-keychain")
            .arg(&self.path)
            .output()
            .await
            .map_err(|e| SetupError::KeychainOperation(
                format!("Failed to delete keychain: {}", e)
            ))?;
        
        if !output.status.success() {
            eprintln!(
                "⚠️  Keychain deletion returned non-zero: {}", 
                String::from_utf8_lossy(&output.stderr)
            );
        }
        
        Ok(())
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        // Best-effort cleanup (fire-and-forget)
        // Cannot block in drop, so spawn detached thread
        let path = self.path.clone();
        std::thread::spawn(move || {
            let _ = std::process::Command::new("security")
                .arg("delete-keychain")
                .arg(&path)
                .output();
        });
    }
}

/// Helper function for security commands
async fn run_security(args: &[&str], keychain_path: &Path) -> Result<()> {
    let mut cmd_args = args.to_vec();
    cmd_args.push(
        keychain_path
            .to_str()
            .ok_or_else(|| SetupError::InvalidConfig("Invalid keychain path".to_string()))?,
    );

    let output = tokio::process::Command::new("security")
        .args(&cmd_args)
        .output()
        .await?;

    if !output.status.success() {
        return Err(SetupError::KeychainOperation(format!(
            "security {} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}
