//! Interactive certificate provisioning workflow

use crate::apple_api;
use crate::config::{CertificateType, DEFAULT_COMMON_NAME, DEFAULT_KEYCHAIN};
use crate::error::{Result, SetupError};
use crate::{error as error_msg, success};
use std::io::{self, Write};
use tempfile::NamedTempFile;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};

use super::super::keychain::{check_for_developer_certificates, import_certificate_to_keychain};
use super::super::prompts::{prompt_for_p8_path, prompt_yes_no};
use super::super::validation::{
    check_dependencies, ensure_config_directory_writable, ensure_keychain_accessible,
};

/// Interactive certificate provisioning workflow
pub async fn interactive_setup() -> Result<()> {
    // Check required dependencies before proceeding
    check_dependencies().await?;

    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = writeln!(&mut buffer, "\n{}", "━".repeat(60));
    let _ = writeln!(
        &mut buffer,
        "Step 1: Checking for existing Developer ID certificate...\n"
    );
    let _ = bufwtr.print(&buffer);

    // Check for existing certificate with robust parsing
    let output = tokio::process::Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .output()
        .await
        .map_err(|e| SetupError::CommandExecution(format!("Failed to check certificates: {e}")))?;

    // Use new parsing function
    match check_for_developer_certificates(output) {
        Ok(certs) if !certs.is_empty() => {
            let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
            let mut buffer = bufwtr.buffer();
            // Colored success output - errors ignored (see module-level docs)
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
            let _ = writeln!(&mut buffer, "✅ Found existing Developer ID certificate!\n");
            let _ = buffer.reset();
            for cert in &certs {
                let _ = writeln!(&mut buffer, "   {cert}");
            }
            let _ = writeln!(&mut buffer);
            let _ = bufwtr.print(&buffer);

            // ASK USER if they want to provision a new certificate
            if !prompt_yes_no("Do you want to provision a new certificate?")? {
                let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
                let mut buffer = bufwtr.buffer();
                let _ = writeln!(&mut buffer, "\nSetup complete! Using existing certificate.");
                let _ = bufwtr.print(&buffer);
                return Ok(());
            }
            // If user says YES, fall through to continue provisioning
        }
        Ok(_) => {
            let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
            let mut buffer = bufwtr.buffer();
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
            let _ = writeln!(&mut buffer, "⚠️  No Developer ID certificate found");
            let _ = buffer.reset();
            let _ = writeln!(
                &mut buffer,
                "   Proceeding with certificate provisioning...\n"
            );
            let _ = bufwtr.print(&buffer);
        }
        Err(e) => {
            // Non-fatal: warn but proceed with provisioning
            let bufwtr = BufferWriter::stderr(ColorChoice::Auto);
            let mut buffer = bufwtr.buffer();
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
            let _ = writeln!(
                &mut buffer,
                "⚠️  Warning: Could not check existing certificates"
            );
            let _ = buffer.reset();
            let _ = writeln!(&mut buffer, "   Error: {e}");
            let _ = writeln!(
                &mut buffer,
                "   Proceeding with certificate provisioning...\n"
            );
            let _ = bufwtr.print(&buffer);
        }
    }

    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = writeln!(&mut buffer, "\n{}", "━".repeat(60));
    let _ = writeln!(&mut buffer, "Step 2: App Store Connect API Setup\n");
    let _ = writeln!(
        &mut buffer,
        "To provision a certificate, you need API credentials from:"
    );
    let _ = writeln!(
        &mut buffer,
        "  https://appstoreconnect.apple.com/access/api\n"
    );
    let _ = writeln!(&mut buffer, "Instructions:");
    let _ = writeln!(&mut buffer, "  1. Click the '+' button to create a new key");
    let _ = writeln!(&mut buffer, "  2. Name it 'Kodegen Signing' (or similar)");
    let _ = writeln!(&mut buffer, "  3. Select 'Developer' role");
    let _ = writeln!(&mut buffer, "  4. Click 'Generate'");
    let _ = writeln!(
        &mut buffer,
        "  5. Download the .p8 file (can only download once!)"
    );
    let _ = writeln!(
        &mut buffer,
        "  6. Note the Key ID and Issuer ID from the page\n"
    );
    let _ = writeln!(&mut buffer, "{}", "━".repeat(60));
    let _ = bufwtr.print(&buffer);

    if !prompt_yes_no("\nDo you have your API credentials ready?")? {
        let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
        let mut buffer = bufwtr.buffer();
        let _ = writeln!(
            &mut buffer,
            "\nSetup paused. Run 'kodegen-setup --interactive' when ready."
        );
        let _ = bufwtr.print(&buffer);
        return Ok(());
    }

    // Collect credentials
    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = writeln!(&mut buffer, "\n{}", "━".repeat(60));
    let _ = writeln!(&mut buffer, "Enter your API credentials:\n");
    let _ = bufwtr.print(&buffer);

    print!("Issuer ID: ");
    io::stdout().flush()?;
    let mut issuer_id = String::new();
    io::stdin().read_line(&mut issuer_id)?;
    let issuer_id = issuer_id.trim();

    print!("Key ID: ");
    io::stdout().flush()?;
    let mut key_id = String::new();
    io::stdin().read_line(&mut key_id)?;
    let key_id = key_id.trim();

    let key_path = if let Some(path) = prompt_for_p8_path().await? {
        path
    } else {
        println!("\nSetup cancelled by user.");
        return Ok(());
    };

    // Create API client
    println!();
    success!("Validating credentials...");

    let client =
        apple_api::AppleAPIClient::new(key_id, issuer_id, std::path::Path::new(&key_path)).await?;

    // ===== PRE-FLIGHT VALIDATION (prevents orphaned certificates) =====
    success!("Validating API credentials...");
    client.test_credentials()?;

    success!("Checking keychain accessibility...");
    ensure_keychain_accessible("login.keychain-db").await?;

    success!("Verifying config directory permissions...");
    ensure_config_directory_writable().await?;

    // All preconditions validated - safe to proceed
    // ===== END PRE-FLIGHT VALIDATION =====

    // Generate CSR
    success!("Generating certificate signing request...");

    let (csr_pem, private_key_pem) = apple_api::generate_csr(DEFAULT_COMMON_NAME)?;

    // Request certificate
    success!("Requesting certificate from Apple...");

    let cert_der = client.request_certificate(&csr_pem, CertificateType::DeveloperIdApplication).await?;

    // Inform user about keychain customization
    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = writeln!(
        &mut buffer,
        "\nℹ️  Using default keychain: {DEFAULT_KEYCHAIN}"
    );
    let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(
        &mut buffer,
        "   To customize, edit ~/.config/kodegen/signing.toml after setup"
    );
    let _ = buffer.reset();
    let _ = bufwtr.print(&buffer);

    // Import to keychain
    success!("Installing certificate to Keychain...");

    if let Err(e) = import_certificate_to_keychain(
        &cert_der,
        &private_key_pem,
        "login.keychain-db",
        DEFAULT_COMMON_NAME,
    ).await {
        error_msg!("Certificate was created in Apple Developer account");
        eprintln!("   but could not be imported to keychain: {e}");
        eprintln!("\n⚠️  Manual cleanup required:");
        eprintln!("   1. Visit https://appstoreconnect.apple.com/access/api");
        eprintln!("   2. Go to Certificates section");
        eprintln!("   3. Delete the newly created certificate");
        eprintln!("   4. Fix the keychain issue and retry setup");
        return Err(e);
    }

    // Save config with secure permissions
    let config_dir = dirs::config_dir()
        .ok_or_else(|| {
            SetupError::MissingConfig("Could not determine config directory".to_string())
        })?
        .join("kodegen");
    tokio::fs::create_dir_all(&config_dir).await?;

    // Set secure directory permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_perms = std::fs::Permissions::from_mode(0o700);
        tokio::fs::set_permissions(&config_dir, dir_perms).await?;
    }

    let config_path = config_dir.join("signing.toml");
    let config_content = format!(
        "# Kodegen Signing Configuration\n\
         # Generated by interactive setup\n\
         \n\
         [macos]\n\
         api_key_id = \"{key_id}\"\n\
         api_issuer_id = \"{issuer_id}\"\n\
         api_key_path = \"{key_path}\"\n\
         keychain = \"{DEFAULT_KEYCHAIN}\"\n\
         common_name = \"{DEFAULT_COMMON_NAME}\"\n\
         # certificate_type = \"developer_id\"  # or \"mac_app_distribution\"\n"
    );

    // Atomic write using temp file + rename
    let mut temp_file = NamedTempFile::new_in(&config_dir)?;
    temp_file.write_all(config_content.as_bytes())?;
    temp_file.flush()?;
    temp_file
        .persist(&config_path)
        .map_err(|e| SetupError::Io(e.error))?;

    // Set secure file permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&config_path, file_perms).await?;
    }

    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();
    let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
    let _ = writeln!(&mut buffer, "\n✅ Certificate installed successfully!");
    let _ = buffer.reset();
    let _ = writeln!(
        &mut buffer,
        "Configuration saved to: {}",
        config_path.display()
    );
    let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
    let _ = writeln!(
        &mut buffer,
        "\n✅ Setup complete! You can now run 'cargo build --package kodegen_daemon'"
    );
    let _ = buffer.reset();
    let _ = bufwtr.print(&buffer);

    Ok(())
}
