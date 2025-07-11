//! Legacy cryptography implementation using multiple crates
//! This is the original implementation for backward compatibility

#[cfg(feature = "legacy-crypto")]
use blake3::{Hash, Hasher};
#[cfg(feature = "legacy-crypto")]
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305 as ChaCha20Poly1305Cipher, Nonce,
};
#[cfg(feature = "legacy-crypto")]
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "legacy-crypto")]
use hkdf::Hkdf;
#[cfg(feature = "legacy-crypto")]
use rand::{rngs::OsRng, RngCore};
#[cfg(feature = "legacy-crypto")]
use sha2::Sha256;
#[cfg(feature = "legacy-crypto")]
use subtle::ConstantTimeEq;
#[cfg(feature = "legacy-crypto")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
#[cfg(feature = "legacy-crypto")]
use zeroize::Zeroize;

use super::{Result, Signature};

/// Ed25519 key pair for signing operations
#[cfg(feature = "legacy-crypto")]
#[derive(Debug)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

#[cfg(feature = "legacy-crypto")]
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

    /// Create from private key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature(signature.to_bytes().to_vec())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if signature.0.len() != 64 {
            return false;
        }
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature.0);
        
        match ed25519_dalek::Signature::from_bytes(&sig_bytes) {
            Ok(sig) => self.verifying_key.verify(message, &sig).is_ok(),
            Err(_) => false,
        }
    }
}

/// X25519 key pair for ECDH operations
#[cfg(feature = "legacy-crypto")]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

#[cfg(feature = "legacy-crypto")]
impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let private_key = X25519PrivateKey::new(&mut OsRng);
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

/// ChaCha20Poly1305 AEAD cipher
#[cfg(feature = "legacy-crypto")]
pub struct ChaCha20Poly1305 {
    cipher: ChaCha20Poly1305Cipher,
}

#[cfg(feature = "legacy-crypto")]
impl ChaCha20Poly1305 {
    /// Create new cipher with key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305Cipher::new(key.into());
        Self { cipher }
    }

    /// Encrypt plaintext with nonce
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
    }

    /// Decrypt ciphertext with nonce
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }
}

/// BLAKE3 hasher
#[cfg(feature = "legacy-crypto")]
pub struct Blake3 {
    hasher: Hasher,
}

#[cfg(feature = "legacy-crypto")]
impl Blake3 {
    /// Create new hasher
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
        }
    }

    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize hash
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    /// Hash data in one go
    pub fn hash(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }
}

/// HKDF key derivation
#[cfg(feature = "legacy-crypto")]
pub struct HkdfExpander;

#[cfg(feature = "legacy-crypto")]
impl HkdfExpander {
    /// Expand key material
    pub fn expand(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], okm: &mut [u8]) -> Result<()> {
        let hkdf = Hkdf::<Sha256>::new(salt, ikm);
        hkdf.expand(info, okm)
            .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))
    }
}

/// Utility functions
#[cfg(feature = "legacy-crypto")]
impl super::CryptoUtils {
    /// Constant-time comparison
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }
}
