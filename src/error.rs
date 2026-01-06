//! Error types for utsuri-core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtsuriError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Bech32 encoding failed: {0}")]
    Bech32Error(String),

    #[error("Hash computation failed: {0}")]
    HashError(String),

    #[error("Invalid chain type: {0}")]
    InvalidChainType(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

pub type Result<T> = std::result::Result<T, UtsuriError>;

