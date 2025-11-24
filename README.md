<div align="center">
  <img src="assets/img/banner.png" alt="Kodegen AI Banner" width="100%" />
</div>

# kodegen_bundler_sign

**Automated code signing and certificate provisioning for Kodegen daemon**

## Overview

`kodegen_bundler_sign` is a comprehensive tool for managing code signing workflows across macOS, Linux, and Windows platforms. Its primary focus is **macOS**, where it provides automated certificate provisioning through Apple's App Store Connect API, builds and signs privileged helper applications, and manages deployment to GitHub releases.

The package serves three main purposes:

1. **Certificate Provisioning**: Automates the process of obtaining Developer ID Application certificates from Apple using App Store Connect API credentials
2. **Helper App Management**: Builds, signs, packages, and deploys the macOS privileged helper application (`KodegenHelper.app`) that enables the Kodegen daemon to execute administrative tasks
3. **Notarization & Signing**: Provides tools for Apple notarization and direct code signing with entitlements

## Quick Start

### Interactive Setup (Recommended)

```bash
cargo run --package kodegen_bundler_sign -- --interactive
```

This will guide you through:
1. Checking for existing certificates
2. Providing App Store Connect API credentials
3. Generating and requesting a Developer ID certificate
4. Installing it to your keychain

### Build Helper App

```bash
cargo run --package kodegen_bundler_sign -- --build-helper
```

### Build and Upload to GitHub

```bash
export GITHUB_TOKEN="your_token"
cargo run --package kodegen_bundler_sign -- --build-helper --upload
```

### Notarize an App

```bash
export APPLE_API_KEY="your_key_id"
export APPLE_API_ISSUER="your_issuer_id"
export APPLE_API_KEY_PATH="/path/to/AuthKey_XXXXXXXXXX.p8"
cargo run --package kodegen_bundler_sign -- --notarize /path/to/YourApp.app
```

### Sign a Binary

```bash
cargo run --package kodegen_bundler_sign -- --sign /path/to/binary \
  --identity "Developer ID Application: Your Name (TEAM_ID)" \
  --entitlements entitlements.plist
```

## CLI Modes

### 1. Show Configuration

```bash
cargo run --package kodegen_bundler_sign -- --show
```

Displays:
- Developer ID certificates in keychain
- Configuration file location (`~/.config/kodegen/signing.toml`)

### 2. Interactive Setup

```bash
cargo run --package kodegen_bundler_sign -- --interactive
```

Guided setup with prompts for:
- App Store Connect Issuer ID
- API Key ID
- Path to .p8 private key file
- Email address

### 3. Build Helper Mode

```bash
cargo run --package kodegen_bundler_sign -- --build-helper [OPTIONS]
```

Options:
- `--upload`: Upload to GitHub releases
- `--github-token <TOKEN>`: GitHub API token (or use `GITHUB_TOKEN` env var)
- `--output-dir <DIR>`: Output directory (default: `target/helper`)

### 4. Notarization Mode

```bash
cargo run --package kodegen_bundler_sign -- --notarize <PATH> [OPTIONS]
```

Options:
- `--wait <BOOL>`: Wait for notarization to complete (default: true)

**Diagnose notarization setup:**
```bash
cargo run --package kodegen_bundler_sign -- --diagnose-notarization
```

**Environment Variables:**
- `APPLE_API_KEY`: App Store Connect API Key ID (recommended)
- `APPLE_API_ISSUER`: App Store Connect Issuer ID
- `APPLE_API_KEY_PATH`: Path to .p8 file (optional, auto-searches standard locations)
- `APPLE_ID`: Apple ID email (legacy method)
- `APPLE_PASSWORD`: App-specific password (legacy method)
- `APPLE_TEAM_ID`: Team ID (legacy method)

### 5. Direct Signing Mode

```bash
cargo run --package kodegen_bundler_sign -- --sign <BINARY> [OPTIONS]
```

Options:
- `--identity <IDENTITY>`: Signing identity (required)
- `--entitlements <PATH>`: Path to entitlements.plist (optional)
- `--hardened-runtime <BOOL>`: Enable hardened runtime (default: true)

### 6. Config File Mode

```bash
cargo run --package kodegen_bundler_sign -- --config signing.toml
```

Example `signing.toml`:
```toml
platform = "macos"
dry_run = false
verbose = true

issuer_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
key_id = "XXXXXXXXXX"
private_key_path = "~/.keys/AuthKey_XXXXXXXXXX.p8"
certificate_type = "developer_id"
common_name = "Kodegen Helper"
keychain = "login.keychain-db"
```

## Architecture

### Core Modules

- **`lib.rs`**: Library interface with platform-conditional exports and shared utilities
- **`main.rs`**: CLI application with six operational modes (show, interactive, build-helper, notarize, sign, config)
- **`config.rs`**: Configuration structures for all platforms
- **`error.rs`**: Custom error types using `thiserror`

### Platform-Specific Modules

#### macOS (`src/macos/`)
- **`setup.rs`**: Certificate provisioning workflow
- **`keychain.rs`**: Keychain operations with file locking
- **`notarization.rs`**: Apple notarization workflow (submit, poll, staple)
- **`validation.rs`**: Certificate and setup validation
- **`prompts.rs`**: Interactive user prompts
- **`mod.rs`**: Module exports and platform entry point

#### Build & Packaging (macOS)
- **`build_helper.rs`**: macOS helper app creation and C code compilation
- **`sign_helper.rs`**: Code signing operations with codesign
- **`package_helper.rs`**: ZIP packaging and integrity hashing
- **`apple_api.rs`**: App Store Connect API client

#### Cross-Platform
- **`windows.rs`**: Cross-platform Authenticode signing using `osslsigncode` (available on all platforms, not just Windows)
- **`linux.rs`**: GPG-based signing guidance

## Apple API Integration

### App Store Connect API Client

The `apple_api.rs` module implements JWT-based authentication with Apple's certificate provisioning API.

#### Authentication Flow

1. **Load .p8 Private Key**: ECDSA ES256 private key from App Store Connect
2. **Generate JWT Token**:
   - Algorithm: ES256
   - Header: `kid` (Key ID), `alg: "ES256"`
   - Claims: `iss` (Issuer ID), `aud: "appstoreconnect-v1"`, `iat`, `exp` (20 minutes)
3. **Sign JWT**: Sign with private key using `jsonwebtoken` crate
4. **API Request**: Include JWT as Bearer token in Authorization header

#### Certificate Request API

**Endpoint**: `https://api.appstoreconnect.apple.com/v1/certificates`

**Request**:
```json
{
  "data": {
    "type": "certificates",
    "attributes": {
      "certificateType": "DEVELOPER_ID_APPLICATION",
      "csrContent": "<PEM-encoded CSR>"
    }
  }
}
```

**Response**:
```json
{
  "data": {
    "attributes": {
      "certificateContent": "<base64-encoded DER certificate>"
    }
  }
}
```

## Certificate Provisioning Workflow

### Prerequisites

1. **Apple Developer Account** with Admin or Developer role
2. **Create App Store Connect API Key**:
   - Navigate to [App Store Connect](https://appstoreconnect.apple.com/access/api)
   - Go to: Users and Access → Keys → App Store Connect API
   - Click "+" to create new key
   - Name: "Kodegen Signing"
   - Access: **Developer** role
   - Download `.p8` file (**one-time download only**)
   - Note the **Key ID** (10 alphanumeric characters)
   - Note the **Issuer ID** (UUID format)

### Automated Provisioning Process

1. **API Authentication**: JWT generation with ES256 signature (20-minute lifetime)
2. **CSR Generation**: RSA key pair with `rcgen`
3. **Request Certificate**: POST CSR to Apple's API
4. **Create P12 Bundle**: Using OpenSSL
5. **Import to Keychain**: With file locking to prevent race conditions
6. **Save Configuration**: To `~/.config/kodegen/signing.toml`
7. **Cleanup**: Remove temporary files

## Helper App Architecture

### Purpose

`KodegenHelper.app` is a macOS privileged helper that enables the Kodegen daemon to execute administrative tasks without running the entire daemon as root. It follows macOS best practices for privilege separation using the Service Management framework.

### Security Model

**Authorization Requirements**:
- Helper requires `admin` group membership
- Daemon identity must match `SMAuthorizedClients` in Info.plist
- Helper identity must match `SMPrivilegedExecutables` in daemon's Info.plist
- Code signature verification enforced by macOS

**Runtime Security**:
- **Parent Process Validation**: Uses `proc_pidpath` to verify parent is `kodegend`
- **Script Size Limit**: Maximum 1MB (1,048,576 bytes)
- **Execution Timeout**: 5 minutes enforced via `SIGALRM`
- **Temporary File Security**: Uses `mkstemp` for secure random filenames
- **Secure Permissions**: Files remain 0600 (owner-only) throughout execution
- **Automatic Cleanup**: Removes temporary files after execution

### C Source Code Implementation

The helper is implemented in C and compiled with `cc`. Key features:

**Main Function Flow**:
```c
1. Validate parent process name contains "kodegen" (macOS: proc_pidpath)
2. Accept script content as argv[1]
3. Validate script size <= 1MB
4. Set up SIGALRM timeout handler (300 seconds)
5. Create temporary file with mkstemp: /tmp/kodegend_helper_XXXXXX
6. Write script content (0600 permissions preserved for security)
7. Fork child process
8. Child: execl("/bin/sh", "sh", temp_path, NULL)
9. Parent: waitpid for completion
10. Clean up temporary file
11. Return child exit status
```

**Error Handling**:
- Exit code 1: Validation or setup failures
- Exit code 124: Timeout reached
- Exit code 128 + N: Killed by signal N
- Otherwise: Child process exit code

### App Bundle Structure

```
KodegenHelper.app/
├── Contents/
│   ├── Info.plist          # Bundle metadata
│   └── MacOS/
│       └── KodegenHelper   # Compiled C executable
```

### Info.plist Configuration

**Key Settings**:
- Bundle ID: `ai.kodegen.kodegend.helper`
- LSUIElement: `true` (background agent, no dock icon)
- Minimum macOS: 10.15

**Authorization Settings**:
```xml
<key>SMPrivilegedExecutables</key>
<dict>
    <key>ai.kodegen.kodegend.helper</key>
    <string>identifier "ai.kodegen.kodegend.helper" and anchor apple generic</string>
</dict>
<key>SMAuthorizedClients</key>
<array>
    <string>identifier "ai.kodegen.kodegend" and anchor apple generic</string>
</array>
```

## Code Signing Process

### Signing Workflow

The `sign_helper.rs` module implements a multi-step signing process:

1. **Certificate Check**: `security find-identity -v -p codesigning`
   - Falls back to ad-hoc signing (`-`) for development if no Developer ID found
2. **Entitlements Creation**: Generates `helper.entitlements` with admin authorization requirements
3. **Sign Executable**: `codesign --force --sign <identity> --options runtime --entitlements helper.entitlements Contents/MacOS/KodegenHelper`
4. **Sign App Bundle**: `codesign --force --deep --sign <identity> --options runtime KodegenHelper.app`
5. **Verify Signature**: `codesign --verify --deep --strict KodegenHelper.app`

### Signing Identities

**Production**:
- Identity: "Developer ID Application: Your Name (TEAM_ID)"
- Obtained via automated provisioning or manual certificate installation

**Development**:
- Identity: "-" (ad-hoc signing)
- Set via: `export KODEGEN_SIGNING_IDENTITY="-"`
- Warnings instead of errors for signing failures

### Hardened Runtime

All production builds use `--options runtime` flag, enabling:
- Library validation
- Hardened runtime protections
- Required for notarization

## Notarization

### Notarization Workflow

Apple notarization is a security process where Apple scans your app for malware and signs it with a notarization ticket.

**Submit for notarization:**
```bash
cargo run --package kodegen_bundler_sign -- --notarize /path/to/App.app
```

**Non-blocking submission:**
```bash
cargo run --package kodegen_bundler_sign -- --notarize /path/to/App.app --wait false
```

**Diagnose setup issues:**
```bash
cargo run --package kodegen_bundler_sign -- --diagnose-notarization
```

### Authentication Methods

**Modern (Recommended)**: App Store Connect API Key
```bash
export APPLE_API_KEY="XXXXXXXXXX"
export APPLE_API_ISSUER="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPLE_API_KEY_PATH="/path/to/AuthKey_XXXXXXXXXX.p8"
```

**Legacy**: Apple ID with app-specific password
```bash
export APPLE_ID="your@email.com"
export APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export APPLE_TEAM_ID="XXXXXXXXXX"
```

### Process Flow

1. **Upload**: App is uploaded to Apple's notarization service using `xcrun notarytool submit`
2. **Poll**: Tool polls for completion status
3. **Staple**: On success, notarization ticket is stapled to the app using `xcrun stapler staple`

## Packaging and Distribution

### ZIP Creation

The `package_helper.rs` module creates compressed packages:

**Features**:
- Compression: Deflated (standard ZLIB)
- Unix Permissions: 0755 preserved
- Recursive directory traversal
- Maintains app bundle structure

**Output Files**:
- `KodegenHelper.app.zip`: Compressed app bundle
- `KodegenHelper.app.zip.sha256`: SHA-256 integrity hash (hex-encoded)
- `app_zip_data.rs`: Generated Rust code with `include_bytes!` macro

### Integrity Verification

**Hash Generation**:
```bash
SHA256(KodegenHelper.app.zip) = <64-character hex string>
```

**Verification Process**:
- Checks for required files: Info.plist, executable
- Validates executable is not empty
- Verifies all files readable without corruption
- Ensures Info.plist is at least 100 bytes

### Build System Integration

**Generated Rust Code**:
```rust
const APP_ZIP_DATA: &[u8] = include_bytes!("/path/to/KodegenHelper.app.zip");
```

**Cargo Environment Variables**:
- `HELPER_ZIP_PATH`: Path to ZIP file
- `HELPER_ZIP_INCLUDE_FILE`: Path to generated Rust file
- `MACOS_HELPER_ZIP_HASH`: SHA-256 hash

### Atomic Operations

All build operations are atomic:

1. Create temporary working directory
2. Validate output directory is writable
3. Build and sign helper app
4. Validate helper structure
5. Create ZIP in temporary location
6. Verify ZIP integrity
7. **Atomic rename** to final location
8. Cleanup temporary files (success or failure)

**Rollback on Failure**: All temporary files removed if any step fails.

## GitHub Integration

### Upload Process

**Target Repository**: `cyrup-ai/kodegen`

**Workflow**:
1. Build and sign helper app
2. Create ZIP package
3. Calculate SHA-256 hash
4. Detect system architecture (e.g., `aarch64`, `x86_64`)
5. Get latest release via GitHub API
6. Upload as asset: `KodegenHelper.app-macos-{arch}.zip`

**Authentication**:
- GitHub token via `--github-token` flag
- Or `GITHUB_TOKEN` environment variable
- Requires `repo` scope for releases

**Upload Command**:
```bash
cargo run --package kodegen_bundler_sign -- \
  --build-helper \
  --upload \
  --github-token "ghp_xxxxxxxxxxxxxxxxxxxx"
```

### Asset Naming Convention

Format: `KodegenHelper.app-macos-{arch}.zip`

Examples:
- `KodegenHelper.app-macos-aarch64.zip` (Apple Silicon)
- `KodegenHelper.app-macos-x86_64.zip` (Intel)

## Windows Cross-Platform Signing

The `windows` module provides **cross-platform** Authenticode signing using `osslsigncode`, available on **all platforms** (not just Windows). This enables macOS and Linux developers to sign Windows binaries.

### Usage

```rust
use kodegen_bundler_sign::windows::{SignConfig, sign_binary_with_fallback};

let config = SignConfig {
    cert_path: "path/to/cert.pfx".into(),
    key_path: None,  // Not needed for PKCS#12
    password: Some("password".to_string()),
    timestamp_url: Some("http://timestamp.digicert.com".to_string()),
    app_name: Some("MyApp".to_string()),
    app_url: Some("https://example.com".to_string()),
};

sign_binary_with_fallback(Path::new("myapp.exe"), &config).await?;
```

### Features

- **Automatic Fallback**: Tries multiple timestamp servers if primary fails
- **Last Resort**: Signs without timestamp if all servers fail
- **Cross-Platform**: Uses `osslsigncode` for non-Windows platforms
- **Certificate Formats**: Supports PEM, PFX/PKCS#12

### Timestamp Servers

Built-in fallback list includes:
- DigiCert
- Sectigo (Comodo)
- GlobalSign
- Others

## Dependencies

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `clap` | 4 | Command-line argument parsing with derive macros |
| `anyhow` | 1 | Error handling with context |
| `serde` | 1 | Serialization framework |
| `serde_json` | 1 | JSON parsing |
| `toml` | 0.9 | TOML configuration parsing |
| `thiserror` | 2 | Custom error types |
| `tokio` | 1 | Async runtime (full feature set) |
| `tempfile` | 3 | Secure temporary file creation |

### macOS-Specific Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `rcgen` | 0.14 | CSR and key pair generation |
| `jsonwebtoken` | 9 | JWT creation with ES256 |
| `base64` | 0.22 | Base64 encoding/decoding |
| `reqwest` | 0.12 | HTTP client for Apple API |
| `dirs` | 6 | Platform-specific paths |
| `shellexpand` | 3 | Tilde expansion |

### Build & Packaging Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `cc` | 1 | C code compilation |
| `zip` | 6 | ZIP archive creation |
| `sha2` | 0.10 | SHA-256 hashing |
| `hex` | 0.4 | Hexadecimal encoding |
| `bytes` | 1 | Byte buffers for uploads |

### Security & Reliability Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `fs4` | 0.13 | File locking with async support |
| `rand` | 0.9 | Random password generation |
| `zeroize` | 1 | Secure memory clearing |
| `chrono` | 0.4 | Certificate expiry handling |

### Integration Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `kodegen_tools_github` | local | GitHub API client |
| `octocrab` | 0.47 | GitHub API library |
| `cyrup_termcolor` | 2 | Terminal colors (required) |
| `which` | 8 | Binary path finding for osslsigncode |

### System Dependencies (macOS)

- **OpenSSL**: PKCS#12 bundle creation (`openssl` command)
- **Security Framework**: Keychain management (`security` command)
- **Codesign**: Code signature operations (`codesign` command)
- **Xcode Command Line Tools**: C compiler (`cc` command)
- **Notarytool**: Apple notarization (`xcrun notarytool`)
- **Stapler**: Notarization ticket stapling (`xcrun stapler`)

## Platform Support

### macOS (Full Support ✅)

**Features**:
- Automated certificate provisioning
- App Store Connect API integration
- Helper app building and compilation
- Code signing with Developer ID
- Apple notarization (submit, poll, staple)
- Direct binary signing with entitlements
- Hardened runtime support
- ZIP packaging with integrity hashing
- GitHub release uploads

**Requirements**:
- macOS 10.15 or later
- Xcode Command Line Tools
- Apple Developer Account (for certificate provisioning)
- App Store Connect API key

### Windows (Cross-Platform Support ⚠️)

**Current Implementation**:
- Cross-platform Authenticode signing via `osslsigncode`
- Works on macOS, Linux, and Windows
- Automatic timestamp server fallback
- Supports PEM and PKCS#12 certificates
- Configuration parsing supported
- Guidance for native Windows tools

**Recommendations for Native Windows**:
```bash
# Import certificate
certutil -user -importpfx code_signing_cert.pfx

# View certificates
certmgr.msc
```

### Linux (Minimal Support ⚠️)

**Current Implementation**:
- GPG setup guidance only
- No automated provisioning
- Configuration parsing supported

**Recommendations**:
```bash
# Generate GPG key
gpg --full-generate-key

# List keys
gpg --list-secret-keys --keyid-format LONG
```

## Security Considerations

### Certificate Security

1. **Private Key Protection**
   - Store `.p8` files securely with restricted permissions: `chmod 600`
   - Never commit to version control
   - Use environment variables in CI/CD
   - Rotate API keys periodically

2. **Keychain Security**
   - Certificates stored in macOS Keychain
   - Access Control List restricts to `/usr/bin/codesign`
   - Requires user authentication on first use

3. **JWT Token Security**
   - Tokens expire after 20 minutes
   - Generated on-demand, not stored
   - Signed with ES256 algorithm

### Helper App Security

1. **Code Signing Verification**
   - Hardened Runtime enabled
   - Signature checked by macOS before execution
   - Tampering detected and prevented

2. **Authorization Model**
   - Requires admin group membership
   - Parent process validation
   - Identity matching via Service Management

3. **Execution Limits**
   - 1MB script size limit prevents abuse
   - 5-minute timeout prevents hangs
   - Automatic cleanup prevents file leaks

4. **Input Validation**
   - Parent process name verification
   - Script size validation
   - Proper error handling for all system calls

### GitHub Upload Security

1. **Token Permissions**
   - Minimum: `repo` scope
   - Recommended: Fine-grained token scoped to repository
   - Never expose tokens in logs or error messages

2. **Asset Verification**
   - SHA-256 hash published with release
   - Users should verify hash before use
   - Download only from official releases

## Troubleshooting

### Certificate Provisioning

**Issue**: `Certificate request failed: Unauthorized`

**Solutions**:
- Verify Issuer ID and Key ID are correct
- Ensure `.p8` file is not corrupted
- Check API key has "Developer" role in App Store Connect
- Confirm API key is not revoked

---

**Issue**: `Failed to import to keychain`

**Solutions**:
```bash
# Unlock keychain
security unlock-keychain login.keychain-db

# List keychains
security list-keychains

# Verify OpenSSL installation
which openssl
openssl version
```

---

**Issue**: `No Developer ID certificate found`

**Solutions**:
- Run interactive setup: `cargo run --package kodegen_bundler_sign -- --interactive`
- Or use ad-hoc signing: `export KODEGEN_SIGNING_IDENTITY="-"`

### Helper Building

**Issue**: `Failed to compile helper: cc not found`

**Solutions**:
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Verify installation
cc --version
xcode-select -p
```

---

**Issue**: `Failed to sign executable: code object is not signed at all`

**Solution**: This is a warning in development mode, not an error. The build continues with ad-hoc signing.

---

**Issue**: `Helper validation failed: Helper executable not executable`

**Solutions**:
```bash
# Check permissions
ls -l target/helper/KodegenHelper.app/Contents/MacOS/KodegenHelper

# Fix permissions
chmod +x target/helper/KodegenHelper.app/Contents/MacOS/KodegenHelper
```

### Notarization

**Issue**: `No notarization credentials found in environment`

**Solutions**:
```bash
# Set API key credentials (recommended)
export APPLE_API_KEY="XXXXXXXXXX"
export APPLE_API_ISSUER="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export APPLE_API_KEY_PATH="/path/to/AuthKey_XXXXXXXXXX.p8"

# Or use Apple ID (legacy)
export APPLE_ID="your@email.com"
export APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export APPLE_TEAM_ID="XXXXXXXXXX"
```

---

**Issue**: `Notarization failed`

**Solutions**:
- Run diagnostics: `cargo run --package kodegen_bundler_sign -- --diagnose-notarization`
- Check app is signed with Developer ID
- Verify hardened runtime is enabled
- Ensure all frameworks and executables are signed
- Check notarization log for specific errors

### GitHub Upload

**Issue**: `GitHub token required for upload`

**Solutions**:
```bash
# Set environment variable
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"

# Or use CLI flag
cargo run --package kodegen_bundler_sign -- --build-helper --upload --github-token "ghp_xxx"
```

---

**Issue**: `Failed to get latest release`

**Solutions**:
- Verify repository exists: `cyrup-ai/kodegen`
- Check token has `repo` scope
- Ensure at least one release exists
- Verify network connectivity

## Development

### Local Development Setup

```bash
# 1. Clone repository (adjust path for your setup)
cd kodegen-bundler-sign

# 2. Provision certificate (one-time)
cargo run --package kodegen_bundler_sign -- --interactive

# 3. Build helper app
cargo run --package kodegen_bundler_sign -- --build-helper

# 4. Verify output
ls -lh target/helper/
```

### Testing

```bash
# Run with verbose output (via config file with verbose = true)
cargo run --package kodegen_bundler_sign -- --config signing.toml

# Dry-run mode (via config file with dry_run = true)
cargo run --package kodegen_bundler_sign -- --config signing.toml

# Show current configuration
cargo run --package kodegen_bundler_sign -- --show

# Diagnose notarization setup
cargo run --package kodegen_bundler_sign -- --diagnose-notarization
```

### CI/CD Integration

**GitHub Actions Example**:

```yaml
name: Build Helper

on:
  push:
    branches: [main]
  release:
    types: [created]

jobs:
  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@nightly
        with:
          components: rustfmt, clippy

      - name: Provision Certificate
        env:
          ISSUER_ID: ${{ secrets.APP_STORE_CONNECT_ISSUER_ID }}
          KEY_ID: ${{ secrets.APP_STORE_CONNECT_KEY_ID }}
          PRIVATE_KEY: ${{ secrets.APP_STORE_CONNECT_PRIVATE_KEY }}
        run: |
          echo "$PRIVATE_KEY" > AuthKey.p8
          chmod 600 AuthKey.p8
          cargo run --package kodegen_bundler_sign -- \
            --issuer-id "$ISSUER_ID" \
            --key-id "$KEY_ID" \
            --private-key AuthKey.p8

      - name: Build Helper
        run: |
          cargo run --package kodegen_bundler_sign -- --build-helper

      - name: Upload to Release
        if: github.event_name == 'release'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          cargo run --package kodegen_bundler_sign -- \
            --build-helper \
            --upload
```

## License

See `LICENSE.md` in the repository root.
