//! Setup from existing configuration file

use crate::apple_api;
use crate::config::MacOSSetupConfig;
use crate::error::{Result, SetupError};
use crate::success;
use std::io::Write;
use termcolor::{BufferWriter, ColorChoice, WriteColor};

use super::super::keychain::import_certificate_to_keychain;
use super::super::validation::{check_dependencies, ensure_keychain_accessible, expand_tilde_path, validate_p8_file};
use super::env_auth::{setup_with_certificate, try_auth_from_env, EnvAuth};

/// Setup from existing configuration file
pub async fn setup_from_config(config: &MacOSSetupConfig, dry_run: bool, verbose: bool) -> Result<()> {
    // Check required dependencies before proceeding
    check_dependencies().await?;

    // NEW: Check for environment variable override (CI/CD takes priority)
    if let Some(env_auth) = try_auth_from_env() {
        match env_auth {
            EnvAuth::Certificate {
                cert_base64,
                password,
            } => {
                if verbose {
                    println!("Using certificate from APPLE_CERTIFICATE environment variable");
                }
                // Store the keychain - it will be cleaned up when function returns
                let _temp_keychain = setup_with_certificate(&cert_base64, &password, dry_run).await?;

                println!("\n✅ Temporary keychain ready for signing operations");
                println!("   Keychain will be deleted when setup completes");

                // The keychain is now available for the rest of this function's lifetime
                // It will auto-cleanup when setup_from_config returns
                return Ok(());
            }
            EnvAuth::ApiKey {
                key_id,
                issuer_id,
                key_path,
            } => {
                if verbose {
                    println!("Using API credentials from environment variables");
                }
                // Override config with env vars - continue with rest of function
                // using env-based config instead of file-based config
                let env_config = MacOSSetupConfig {
                    issuer_id,
                    key_id,
                    private_key_path: key_path,
                    certificate_type: config.certificate_type,
                    common_name: config.common_name.clone(),
                    keychain: config.keychain.clone(),
                };

                // Continue with the rest of this function using env_config
                return continue_setup_from_config(&env_config, dry_run, verbose).await;
            }
        }
    }

    // Continue with regular config-file based setup
    continue_setup_from_config(config, dry_run, verbose).await
}

async fn continue_setup_from_config(
    config: &MacOSSetupConfig,
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    // Create verbose logging helper
    let log = |msg: &str| {
        if verbose {
            let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
            let mut buffer = bufwtr.buffer();
            // Verbose/progress output - errors ignored (see module-level docs)
            let _ = writeln!(&mut buffer, "[VERBOSE] {msg}");
            let _ = bufwtr.print(&buffer);
        }
    };

    log(&format!(
        "Starting setup with config: dry_run={dry_run}, verbose={verbose}"
    ));
    log(&format!("Certificate type: {:?}", config.certificate_type));
    log(&format!("Keychain: {}", config.keychain));

    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = writeln!(
        &mut buffer,
        "Provisioning certificate with provided configuration...\n"
    );
    let _ = bufwtr.print(&buffer);

    // Expand tilde in config path with error checking
    log(&format!(
        "Expanding path: {}",
        config.private_key_path.display()
    ));
    let expanded_path =
        expand_tilde_path(&config.private_key_path.to_string_lossy()).map_err(|e| {
            SetupError::InvalidConfig(format!(
                "Invalid private_key_path in configuration:\n{e}\n\n\
             Config file: ~/.config/kodegen/signing.toml\n\
             Please update private_key_path to use absolute path"
            ))
        })?;
    let key_path = std::path::Path::new(&expanded_path);

    // Validate path before attempting API call
    log(&format!("Validating .p8 file: {expanded_path}"));
    validate_p8_file(key_path).await.map_err(|e| {
        SetupError::InvalidConfig(format!(
            "Invalid private_key_path in configuration:\n{e}\n\n\
             Config file: ~/.config/kodegen/signing.toml\n\
             Please update the private_key_path setting"
        ))
    })?;

    // Dry-run mode implementation
    if dry_run {
        let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
        let mut buffer = bufwtr.buffer();
        let _ = buffer.set_color(termcolor::ColorSpec::new().set_fg(Some(termcolor::Color::Cyan)));
        let _ = writeln!(&mut buffer, "\n🔍 DRY RUN MODE - No changes will be made");
        let _ = buffer.reset();
        let _ = bufwtr.print(&buffer);

        log("Validating API credentials");
        let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
        let mut buffer = bufwtr.buffer();
        let _ = writeln!(&mut buffer, "\n✓ Validating Apple API credentials...");
        let _ = bufwtr.print(&buffer);

        // Create client and test credentials
        let client = apple_api::AppleAPIClient::new(&config.key_id, &config.issuer_id, key_path).await?;

        client.test_credentials()?;

        success!("API credentials are valid");

        // Show what would happen
        let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
        let mut buffer = bufwtr.buffer();
        let _ = writeln!(&mut buffer, "\n📋 Would perform these actions:");
        let _ = writeln!(
            &mut buffer,
            "  1. Generate CSR with Common Name: {}",
            config.common_name
        );
        let _ = writeln!(
            &mut buffer,
            "  2. Request certificate type: {:?}",
            config.certificate_type
        );
        let _ = writeln!(
            &mut buffer,
            "  3. Import certificate to keychain: {}",
            config.keychain
        );
        let _ = writeln!(
            &mut buffer,
            "\n✅ Dry-run validation complete - configuration is valid"
        );
        let _ = bufwtr.print(&buffer);

        return Ok(());
    }

    // Create API client with validated path
    log(&format!(
        "Creating Apple API client (key_id: {})",
        config.key_id
    ));
    let client = apple_api::AppleAPIClient::new(&config.key_id, &config.issuer_id, key_path).await?;

    // ===== PRE-FLIGHT VALIDATION (prevents orphaned certificates) =====
    log("Validating API credentials");
    client.test_credentials()?;

    log(&format!(
        "Checking keychain accessibility: {}",
        config.keychain
    ));
    ensure_keychain_accessible(&config.keychain).await?;

    // Note: setup_from_config doesn't save config file, so no directory check needed
    // ===== END PRE-FLIGHT VALIDATION =====

    log("Generating certificate signing request");
    let (csr_pem, private_key_pem) = apple_api::generate_csr(&config.common_name)?;

    if verbose {
        log(&format!("CSR length: {} bytes", csr_pem.len()));
        log(&format!(
            "Private key length: {} bytes",
            private_key_pem.len()
        ));
    }

    log("Requesting certificate from Apple API");
    success!("Requesting certificate from Apple...");

    let cert_der = client.request_certificate(&csr_pem, config.certificate_type).await?;

    if verbose {
        log(&format!("Received certificate: {} bytes", cert_der.len()));
    }

    success!("Installing to keychain...");

    import_certificate_to_keychain(
        &cert_der,
        &private_key_pem,
        &config.keychain,
        &config.common_name,
    ).await?;

    println!();
    success!("✅ Certificate provisioned successfully!");

    Ok(())
}
