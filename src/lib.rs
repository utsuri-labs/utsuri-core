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
//! let keypair = crypto::derive_keypair("signature_hex", "domain");
//! let address = crypto::pubkey_to_address(&keypair.public_key, "utsuri");
//! ```

pub mod crypto;
pub mod error;

pub use crypto::*;
pub use error::*;

