//! Cryptographic functions for Utsuri
//!
//! Provides:
//! - Key derivation from signatures
//! - Cosmos transaction signing
//! - Address generation
//! - Hash functions

use k256::ecdsa::{SigningKey, Signature, signature::hazmat::PrehashSigner};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use bech32::{Bech32, Hrp};

use crate::error::{UtsuriError, Result};

/// A derived keypair from a signature
#[derive(Debug, Clone)]
pub struct DerivedKeypair {
    /// Private key (32 bytes, hex)
    pub private_key: String,
    /// Compressed public key (33 bytes, hex)
    pub public_key: String,
    /// Bech32-encoded address
    pub address: String,
}

/// Derive a Cosmos keypair from a signature.
///
/// Uses a two-step HKDF-like construction:
///   privateKey = SHA256(SHA256(signature) || domain_separator)
///
/// This ensures deterministic derivation from the same signature.
///
/// # Arguments
/// * `signature_hex` - The signature bytes in hex (0x prefix optional)
/// * `domain_sep` - Domain separator string for key derivation
/// * `bech32_prefix` - Bech32 prefix for the address (e.g., "utsuri")
///
/// # Returns
/// A `DerivedKeypair` containing private key, public key, and address
pub fn derive_keypair(
    signature_hex: &str,
    domain_sep: &str,
    bech32_prefix: &str,
) -> Result<DerivedKeypair> {
    // Decode signature
    let sig_hex = signature_hex.trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| UtsuriError::InvalidHex(e.to_string()))?;

    // Two-step hash: SHA256(SHA256(signature) || domain_separator)
    // First hash: normalize the signature
    let mut h1 = Sha256::new();
    h1.update(&sig_bytes);
    let hash1 = h1.finalize();

    // Second hash: add domain separator
    let mut h2 = Sha256::new();
    h2.update(&hash1);
    h2.update(domain_sep.as_bytes());
    let hash = h2.finalize();

    // Create signing key from hash
    let signing_key = SigningKey::from_bytes((&hash[..]).into())
        .map_err(|e| UtsuriError::KeyDerivationFailed(e.to_string()))?;

    // Get public key (compressed)
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_encoded_point(true);
    let public_key_hex = hex::encode(public_key_bytes.as_bytes());

    // Derive address
    let address = pubkey_to_address(public_key_bytes.as_bytes(), bech32_prefix)?;

    Ok(DerivedKeypair {
        private_key: hex::encode(&hash),
        public_key: public_key_hex,
        address,
    })
}

/// Convert a public key to a bech32 address.
///
/// Uses the standard Cosmos address derivation:
/// address = RIPEMD160(SHA256(pubkey))
///
/// # Arguments
/// * `pubkey_bytes` - Compressed public key bytes (33 bytes)
/// * `prefix` - Bech32 prefix (e.g., "utsuri", "cosmos")
pub fn pubkey_to_address(pubkey_bytes: &[u8], prefix: &str) -> Result<String> {
    // SHA256 -> RIPEMD160
    let mut sha_hasher = Sha256::new();
    sha_hasher.update(pubkey_bytes);
    let sha_hash = sha_hasher.finalize();

    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha_hash);
    let ripemd_hash = ripemd_hasher.finalize();

    // Bech32 encode
    let hrp = Hrp::parse(prefix)
        .map_err(|e| UtsuriError::Bech32Error(format!("Invalid prefix: {}", e)))?;
    let address = bech32::encode::<Bech32>(hrp, &ripemd_hash)
        .map_err(|e| UtsuriError::Bech32Error(e.to_string()))?;

    Ok(address)
}

/// Sign a Cosmos transaction.
///
/// The message should be the SignDoc bytes. This function:
/// 1. SHA256 hashes the message
/// 2. Signs the hash with the private key
///
/// # Arguments
/// * `privkey_hex` - Private key in hex
/// * `message` - SignDoc bytes to sign
///
/// # Returns
/// Signature bytes (64 bytes, r || s)
pub fn sign_cosmos(privkey_hex: &str, message: &[u8]) -> Result<Vec<u8>> {
    // Decode private key
    let privkey_hex = privkey_hex.trim_start_matches("0x");
    let privkey_bytes = hex::decode(privkey_hex)
        .map_err(|e| UtsuriError::InvalidHex(e.to_string()))?;

    // Create signing key
    let signing_key = SigningKey::from_bytes((&privkey_bytes[..]).into())
        .map_err(|e| UtsuriError::KeyDerivationFailed(e.to_string()))?;

    // Hash the message (Cosmos SDK hashes SignDoc with SHA256)
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();

    // Sign the hash (use sign_prehash to avoid double-hashing)
    let signature: Signature = signing_key.sign_prehash(&hash)
        .map_err(|e| UtsuriError::SigningFailed(e.to_string()))?;

    Ok(signature.to_bytes().to_vec())
}

/// Compute SHA256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute RIPEMD160 hash
pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ============================================================================
// Deterministic Address Derivation (matches x/account/types/address.go)
// ============================================================================

/// Supported chain types for address derivation
pub const CHAIN_TYPE_EVM: &str = "evm";
pub const CHAIN_TYPE_SOLANA: &str = "solana";
pub const CHAIN_TYPE_COSMOS: &str = "cosmos";

/// Derive a deterministic Utsuri address from an external address.
/// 
/// The same external address will always produce the same Utsuri address.
/// This matches the on-chain derivation in `x/account/types/address.go`.
///
/// Algorithm: SHA256(normalized_input) -> RIPEMD160 -> bech32("utsuri", hash)
///
/// # Arguments
/// * `chain_type` - Chain type: "evm", "solana", or "cosmos"
/// * `external_address` - The external address (hex for EVM, base58 for Solana, bech32 for Cosmos)
///
/// # Returns
/// The derived Utsuri bech32 address
pub fn derive_utsuri_address(chain_type: &str, external_address: &str) -> Result<String> {
    // Normalize the address to canonical bytes
    let normalized = normalize_external_address(chain_type, external_address)?;
    
    // SHA256 -> RIPEMD160 -> bech32 (same as pubkey_to_address but different input)
    let sha_hash = sha256(&normalized);
    let ripemd_hash = ripemd160(&sha_hash);
    
    // Bech32 encode with "utsuri" prefix
    let hrp = Hrp::parse("utsuri")
        .map_err(|e| UtsuriError::Bech32Error(format!("Invalid prefix: {}", e)))?;
    let address = bech32::encode::<Bech32>(hrp, &ripemd_hash)
        .map_err(|e| UtsuriError::Bech32Error(e.to_string()))?;
    
    Ok(address)
}

/// Normalize an external address to canonical bytes for derivation.
fn normalize_external_address(chain_type: &str, address: &str) -> Result<Vec<u8>> {
    match chain_type {
        CHAIN_TYPE_EVM => normalize_evm_address(address),
        CHAIN_TYPE_SOLANA => normalize_solana_address(address),
        CHAIN_TYPE_COSMOS => normalize_cosmos_address(address),
        _ => Err(UtsuriError::InvalidChainType(chain_type.to_string())),
    }
}

/// Normalize EVM address: lowercase, no 0x prefix, decode to 20 bytes
fn normalize_evm_address(address: &str) -> Result<Vec<u8>> {
    let addr = address.to_lowercase();
    let addr = addr.trim_start_matches("0x");
    
    if addr.len() != 40 {
        return Err(UtsuriError::InvalidAddress(format!(
            "EVM address must be 40 hex chars, got {}", addr.len()
        )));
    }
    
    hex::decode(addr)
        .map_err(|e| UtsuriError::InvalidHex(e.to_string()))
}

/// Normalize Solana address: base58 decode to 32 bytes
fn normalize_solana_address(address: &str) -> Result<Vec<u8>> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| UtsuriError::InvalidAddress(format!("Invalid base58: {}", e)))?;
    
    if bytes.len() != 32 {
        return Err(UtsuriError::InvalidAddress(format!(
            "Solana address must be 32 bytes, got {}", bytes.len()
        )));
    }
    
    Ok(bytes)
}

/// Normalize Cosmos address: bech32 decode to underlying bytes
fn normalize_cosmos_address(address: &str) -> Result<Vec<u8>> {
    let (_, data) = bech32::decode(address)
        .map_err(|e| UtsuriError::InvalidAddress(format!("Invalid bech32: {}", e)))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keypair() {
        // A sample signature (65 bytes when decoded)
        let sig = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00";
        let result = derive_keypair(sig, "test-domain", "utsuri");
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert!(keypair.address.starts_with("utsuri1"));
        assert_eq!(keypair.private_key.len(), 64); // 32 bytes hex
        assert_eq!(keypair.public_key.len(), 66);  // 33 bytes hex (compressed)
    }

    #[test]
    fn test_pubkey_to_address() {
        // A sample compressed public key (33 bytes)
        let pubkey_hex = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let address = pubkey_to_address(&pubkey_bytes, "utsuri").unwrap();
        assert!(address.starts_with("utsuri1"));
    }

    #[test]
    fn test_derive_utsuri_address_evm() {
        // Test EVM address derivation
        let evm_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE87";
        let result = derive_utsuri_address(CHAIN_TYPE_EVM, evm_addr);
        assert!(result.is_ok());
        
        let utsuri_addr = result.unwrap();
        assert!(utsuri_addr.starts_with("utsuri1"));
        
        // Test case insensitivity (should produce same address)
        let lower = "0x742d35cc6634c0532925a3b844bc9e7595f8fe87";
        let result2 = derive_utsuri_address(CHAIN_TYPE_EVM, lower).unwrap();
        assert_eq!(utsuri_addr, result2);
        
        // Test without 0x prefix
        let no_prefix = "742d35cc6634c0532925a3b844bc9e7595f8fe87";
        let result3 = derive_utsuri_address(CHAIN_TYPE_EVM, no_prefix).unwrap();
        assert_eq!(utsuri_addr, result3);
    }

    #[test]
    fn test_derive_utsuri_address_deterministic() {
        // Same input should always produce same output
        let evm_addr = "0xdead000000000000000000000000000000000beef";
        let addr1 = derive_utsuri_address(CHAIN_TYPE_EVM, evm_addr).unwrap();
        let addr2 = derive_utsuri_address(CHAIN_TYPE_EVM, evm_addr).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_utsuri_address_invalid() {
        // Invalid chain type
        let result = derive_utsuri_address("invalid", "0x123");
        assert!(result.is_err());
        
        // Invalid EVM address (too short)
        let result = derive_utsuri_address(CHAIN_TYPE_EVM, "0x1234");
        assert!(result.is_err());
        
        // Invalid EVM address (invalid hex)
        let result = derive_utsuri_address(CHAIN_TYPE_EVM, "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(result.is_err());
    }
}

