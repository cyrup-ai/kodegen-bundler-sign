//! Enhanced code signing with entitlements and hardened runtime

use crate::error::{Result, SetupError};
use std::io::Write;
use std::path::Path;
use termcolor::WriteColor;

/// Sign binary with optional entitlements, hardened runtime, and deep signing
///
/// # Arguments
/// * `binary_path` - Path to binary/app to sign
/// * `signing_identity` - Certificate name or hash
/// * `entitlements_path` - Optional path to entitlements.plist
/// * `hardened_runtime` - Enable hardened runtime (required for notarization)
/// * `deep` - Enable deep signing to recursively sign all nested components
///
/// # Returns
/// * `Ok(())` - Signing succeeded
/// * `Err(SetupError)` - Signing failed
pub async fn sign_with_entitlements(
    binary_path: &Path,
    signing_identity: &str,
    entitlements_path: Option<&Path>,
    hardened_runtime: bool,
    deep: bool,
) -> Result<()> {
    if !binary_path.exists() {
        return Err(SetupError::InvalidConfig(format!(
            "Binary not found: {}",
            binary_path.display()
        )));
    }

    let mut args = vec!["-s", signing_identity];

    // Add hardened runtime flag (required for notarization)
    if hardened_runtime {
        args.push("--options");
        args.push("runtime");
    }

    // Add entitlements if provided
    if let Some(entitlements) = entitlements_path {
        if !entitlements.exists() {
            return Err(SetupError::InvalidConfig(format!(
                "Entitlements file not found: {}",
                entitlements.display()
            )));
        }

        args.push("--entitlements");
        args.push(
            entitlements.to_str().ok_or_else(|| {
                SetupError::InvalidConfig("Invalid entitlements path".to_string())
            })?,
        );
    }

    // Force re-signing
    args.push("--force");

    // Add deep signing if requested (signs all nested components)
    if deep {
        args.push("--deep");
    }

    // Add binary path
    args.push(
        binary_path
            .to_str()
            .ok_or_else(|| SetupError::InvalidConfig("Invalid binary path".to_string()))?,
    );

    // Execute codesign
    let output = tokio::process::Command::new("codesign")
        .args(&args)
        .output()
        .await
        .map_err(|e| SetupError::CommandExecution(format!("codesign failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SetupError::CommandExecution(format!(
            "Code signing failed:\n\
             Command: codesign {}\n\
             Error: {}",
            args.join(" "),
            stderr
        )));
    }

    success!("Signed: {}", binary_path.display());

    // Verify signature
    let verify = tokio::process::Command::new("codesign")
        .args(["--verify", "--verbose"])
        .arg(binary_path)
        .output()
        .await?;

    if verify.status.success() {
        success!("Signature verified");
    }

    Ok(())
}
