//! Certificate validation and expiry checking for macOS

use crate::error::{Result, SetupError};
use chrono::{DateTime, Utc};
use std::path::Path;
use tempfile::TempDir;

/// Parse security find-identity output and extract Developer ID Application certificates
///
/// Returns a vector of certificate names that start with "Developer ID Application:"
///
/// # Arguments
/// * `output` - The complete Command output from security find-identity
///
/// # Returns
/// * `Ok(Vec<String>)` - List of Developer ID certificate names found
/// * `Err(SetupError)` - If command failed or output is invalid UTF-8
///
/// # Example Output Parsing
/// Input: `  1) ABC123... "Developer ID Application: Acme Corp (TEAM123)"`
/// Output: `["Developer ID Application: Acme Corp (TEAM123)"]`
pub fn check_for_developer_certificates(output: std::process::Output) -> Result<Vec<String>> {
    // Validate command succeeded before parsing
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SetupError::CommandExecution(format!(
            "security find-identity failed with status {}: {}",
            output.status.code().unwrap_or(-1),
            stderr
        )));
    }

    // Use strict UTF-8 parsing - fail if output contains invalid UTF-8
    // This is better than lossy which could corrupt certificate names
    let output_str = std::str::from_utf8(&output.stdout).map_err(|e| {
        SetupError::CommandExecution(format!("security command output is not valid UTF-8: {e}"))
    })?;

    let mut developer_certs = Vec::new();

    // Parse each line to extract certificate names
    for line in output_str.lines() {
        let trimmed = line.trim();

        // Skip empty lines and summary line
        if trimmed.is_empty() || trimmed.contains("valid identities found") {
            continue;
        }

        // Extract certificate name from within double quotes
        // Format: `  1) HASH... "Certificate Name Here"`
        if let Some(start_quote) = trimmed.find('"') {
            // Find the closing quote
            if let Some(end_quote) = trimmed[start_quote + 1..].find('"') {
                let cert_name = &trimmed[start_quote + 1..start_quote + 1 + end_quote];

                // Only include Developer ID Application certificates
                if cert_name.starts_with("Developer ID Application:") {
                    developer_certs.push(cert_name.to_string());
                }
            }
        }
    }

    Ok(developer_certs)
}

/// Certificate information with expiry date
pub struct CertificateInfo {
    pub name: String,
    pub sha1_hash: String,
    pub expiry: DateTime<Utc>,
    pub is_valid: bool,
}

/// Check certificate expiry via security command
pub async fn check_certificate_expiry(cert_name: &str) -> Result<CertificateInfo> {
    let output = tokio::process::Command::new("security")
        .args(["find-certificate", "-c", cert_name, "-p"])
        .output()
        .await?;

    if !output.status.success() {
        return Err(SetupError::KeychainOperation(
            "Certificate not found".to_string(),
        ));
    }

    // Parse PEM output and extract expiry using openssl
    let pem_data = String::from_utf8_lossy(&output.stdout);

    // Write to temp file for openssl parsing
    let temp_dir = TempDir::new()?;
    let cert_path = temp_dir.path().join("cert.pem");
    tokio::fs::write(&cert_path, pem_data.as_bytes()).await?;

    // Get expiry date via openssl
    let openssl_out = tokio::process::Command::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(&cert_path)
        .output()
        .await?;

    // Parse: notAfter=Dec 31 23:59:59 2025 GMT
    let date_str = String::from_utf8_lossy(&openssl_out.stdout);
    let expiry_str = date_str
        .strip_prefix("notAfter=")
        .ok_or_else(|| SetupError::CertificateGeneration("Invalid date format".to_string()))?
        .trim();

    let expiry = DateTime::parse_from_str(expiry_str, "%b %d %H:%M:%S %Y %Z")
        .map_err(|e| SetupError::CertificateGeneration(format!("Failed to parse date: {e}")))?
        .with_timezone(&Utc);

    let now = Utc::now();
    let is_valid = expiry > now;

    Ok(CertificateInfo {
        name: cert_name.to_string(),
        sha1_hash: get_cert_hash(&cert_path).await?,
        expiry,
        is_valid,
    })
}

async fn get_cert_hash(cert_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new("openssl")
        .args(["x509", "-fingerprint", "-sha1", "-noout", "-in"])
        .arg(cert_path)
        .output()
        .await?;

    let hash_line = String::from_utf8_lossy(&output.stdout);
    let hash = hash_line
        .strip_prefix("SHA1 Fingerprint=")
        .ok_or_else(|| SetupError::CertificateGeneration("Invalid hash format".to_string()))?
        .trim()
        .replace(':', "");

    Ok(hash)
}
