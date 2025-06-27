//! Cryptographic utilities for GhostLink
//! 
//! This module provides cryptographic functions used by GhostLink,
//! including Ed25519 signing, ChaCha20Poly1305 encryption, and BLAKE3 hashing.

use anyhow::Result;
use blake3::{Hash, Hasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use zeroize::Zeroize;

/// Ed25519 key pair for signing operations
#[derive(Debug)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from a private key seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// X25519 key pair for ECDH operations
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let private_key = X25519PrivateKey::random_from_rng(&mut OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from private key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let private_key = X25519PrivateKey::from(*bytes);
        let public_key = X25519PublicKey::from(&private_key);
        
        Self {
            private_key,
            public_key,
        }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Perform ECDH to derive shared secret
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        self.private_key.diffie_hellman(their_public).to_bytes()
    }

    /// Get the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }
}

/// ChaCha20Poly1305 encryption utilities
pub struct ChaCha20Encryption {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Encryption {
    /// Create new encryption instance with given key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        
        Self { cipher }
    }

    /// Generate a random key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt data with a random nonce
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        Ok([&nonce_bytes[..], &ciphertext].concat())
    }

    /// Decrypt data (nonce is prepended to ciphertext)
    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }
}

/// BLAKE3 hashing utilities
pub struct Blake3Hasher;

impl Blake3Hasher {
    /// Hash data with BLAKE3
    pub fn hash(data: &[u8]) -> Hash {
        blake3::hash(data)
    }

    /// Hash multiple data chunks
    pub fn hash_chunks(chunks: &[&[u8]]) -> Hash {
        let mut hasher = Hasher::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize()
    }

    /// Create keyed hash
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
        blake3::keyed_hash(key, data)
    }

    /// Derive key using BLAKE3 derive_key
    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, key_material)
    }
}

/// HKDF key derivation utilities
pub struct HkdfDerivation;

impl HkdfDerivation {
    /// Derive key using HKDF-SHA256
    pub fn derive_key(
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
        let mut output = vec![0u8; output_length];
        hkdf.expand(info, &mut output)
            .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))?;
        Ok(output)
    }

    /// Derive multiple keys from same material
    pub fn derive_keys(
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        keys: &[(String, usize)], // (context, length) pairs
    ) -> Result<Vec<Vec<u8>>> {
        let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
        
        keys.iter()
            .map(|(context, length)| {
                let mut output = vec![0u8; *length];
                hkdf.expand(context.as_bytes(), &mut output)
                    .map_err(|e| anyhow::anyhow!("HKDF expansion failed for {}: {}", context, e))?;
                Ok(output)
            })
            .collect()
    }
}

/// Utility functions for cryptographic operations
pub mod utils {
    use super::*;

    /// Generate random bytes
    pub fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate random 32-byte key
    pub fn random_key32() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Constant-time comparison
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }

    /// Securely clear memory
    pub fn secure_clear(data: &mut [u8]) {
        data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"test message";
        
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
        
        // Wrong message should fail
        assert!(keypair.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_x25519_keypair() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        
        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());
        
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_chacha20_encryption() {
        let key = ChaCha20Encryption::generate_key();
        let cipher = ChaCha20Encryption::new(&key);
        let plaintext = b"Hello, GhostLink!";
        
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_blake3_hashing() {
        let data = b"test data";
        let hash1 = Blake3Hasher::hash(data);
        let hash2 = Blake3Hasher::hash(data);
        
        assert_eq!(hash1, hash2);
        
        let different_data = b"different data";
        let hash3 = Blake3Hasher::hash(different_data);
        
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";
        
        let key1 = HkdfDerivation::derive_key(ikm, Some(salt), info, 32).unwrap();
        let key2 = HkdfDerivation::derive_key(ikm, Some(salt), info, 32).unwrap();
        
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
