//! Certificate and keychain operations for macOS
//!
//! This module provides functionality for:
//! - Importing certificates and P12 files into keychains
//! - Validating certificates and checking expiry
//! - Creating temporary keychains for CI/CD
//! - Enhanced code signing with entitlements

mod import;
mod signing;
mod temp;
mod validation;

// Re-export public APIs
pub use import::{import_certificate_to_keychain, import_p12_with_lock};
pub use signing::sign_with_entitlements;
pub use temp::TempKeychain;
pub use validation::{check_certificate_expiry, check_for_developer_certificates, CertificateInfo};
