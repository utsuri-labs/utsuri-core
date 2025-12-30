//! Utsuri Core Library
//!
//! Shared cryptographic and utility functions used by:
//! - WASM modules (cosmos-wasm, eth-wasm)
//! - Tauri desktop app
//! - Backend services
//!
//! # Example
//!
//! ```rust
//! use utsuri_core::crypto;
//!
//! // Derive a keypair from a signature
//! let sig_hex = "abcd1234".repeat(16); // 64 bytes hex
//! let keypair = crypto::derive_keypair(&sig_hex, "domain", "utsuri").unwrap();
//! assert!(keypair.address.starts_with("utsuri1"));
//! ```

pub mod crypto;
pub mod error;

pub use crypto::*;
pub use error::*;

