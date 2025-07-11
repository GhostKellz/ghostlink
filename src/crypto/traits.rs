//! Crypto trait definitions for unified API

use anyhow::Result;

/// Ed25519 digital signature operations
pub trait Ed25519Operations {
    type Signature;
    
    /// Generate a new random key pair
    fn generate() -> Self;
    
    /// Create from seed bytes
    fn from_seed(seed: &[u8; 32]) -> Result<Self>
    where
        Self: Sized;
    
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
    
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;
    
    /// Get public key bytes
    fn public_key_bytes(&self) -> [u8; 32];
    
    /// Get private key bytes (use with caution)
    fn private_key_bytes(&self) -> [u8; 32];
}

/// X25519 Elliptic Curve Diffie-Hellman operations
pub trait X25519Operations {
    /// Generate a new random key pair
    fn generate() -> Self;
    
    /// Create from private key bytes
    fn from_bytes(bytes: &[u8; 32]) -> Self;
    
    /// Perform ECDH to derive shared secret
    fn diffie_hellman(&self, their_public: &[u8; 32]) -> [u8; 32];
    
    /// Get public key bytes
    fn public_key_bytes(&self) -> [u8; 32];
}

/// ChaCha20Poly1305 AEAD operations
pub trait AeadOperations {
    /// Create cipher from key
    fn new(key: &[u8; 32]) -> Self;
    
    /// Encrypt plaintext with nonce
    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt ciphertext with nonce
    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// BLAKE3 hashing operations
pub trait Blake3Operations {
    /// Hash input data
    fn hash(data: &[u8]) -> [u8; 32];
    
    /// Create new hasher instance
    fn new() -> Self;
    
    /// Update hasher with data
    fn update(&mut self, data: &[u8]);
    
    /// Finalize and get hash
    fn finalize(&self) -> [u8; 32];
}

/// HKDF key derivation operations
pub trait HkdfOperations {
    /// Extract and expand key material
    fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> Result<Vec<u8>>;
    
    /// Extract step only
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32];
    
    /// Expand step only
    fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>>;
}
