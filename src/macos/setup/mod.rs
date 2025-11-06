//! Main setup workflows for macOS certificate provisioning
//!
//! This module is organized into logical submodules:
//! - `env_auth` - CI/CD authentication from environment variables
//! - `show` - Display current configuration
//! - `interactive` - Interactive setup workflow
//! - `config_setup` - Setup from configuration files
//! - `api_key` - API key file management

mod env_auth;
mod show;
mod interactive;
mod config_setup;
mod api_key;

// Re-export public API
pub use show::show_config;
pub use interactive::interactive_setup;
pub use config_setup::setup_from_config;
pub use api_key::ensure_api_key_file;
