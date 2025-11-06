//! Display current signing configuration and certificate status

use crate::error::{Result, SetupError};
use std::io::Write;
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, WriteColor};
use super::super::keychain::check_for_developer_certificates;

/// Display current signing configuration and certificate status
pub async fn show_config() -> Result<()> {
    // Check for Developer ID certificates using robust parsing
    let output = tokio::process::Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .output()
        .await
        .map_err(|e| {
            SetupError::CommandExecution(format!("Failed to run security command: {e}"))
        })?;

    let bufwtr = BufferWriter::stdout(ColorChoice::Auto);
    let mut buffer = bufwtr.buffer();

    // Parse certificates with proper error handling
    match check_for_developer_certificates(output) {
        Ok(certs) if !certs.is_empty() => {
            // Colored status output - errors ignored (see module-level docs)
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
            let _ = writeln!(
                &mut buffer,
                "✅ Developer ID Certificate: Found {} certificate(s)",
                certs.len()
            );
            let _ = buffer.reset();
            for cert in certs {
                let _ = writeln!(&mut buffer, "   {cert}");
            }
        }
        Ok(_) => {
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
            let _ = writeln!(&mut buffer, "❌ Developer ID Certificate: Not found");
            let _ = buffer.reset();
        }
        Err(e) => {
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
            let _ = writeln!(&mut buffer, "⚠️  Developer ID Certificate: Could not check");
            let _ = buffer.reset();
            let _ = writeln!(&mut buffer, "   Error: {e}");
        }
    }

    // Check for stored credentials
    if let Some(home) = dirs::home_dir() {
        let cred_path = home.join(".config/kodegen/signing.toml");
        if cred_path.exists() {
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
            let _ = writeln!(&mut buffer, "\n✅ Signing Config: {}", cred_path.display());
            let _ = buffer.reset();
        } else {
            let _ = buffer.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
            let _ = writeln!(&mut buffer, "\n❌ Signing Config: Not found");
            let _ = buffer.reset();
        }
    }

    let _ = bufwtr.print(&buffer);
    Ok(())
}
