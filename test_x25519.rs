// Test file to check x25519-dalek 1.1 API (working version)
use ghostlink::crypto::X25519KeyPair;

fn main() {
    println!("Testing x25519-dalek API with ghostlink crypto wrapper...");
    
    // Test key generation
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();
    
    println!("Alice public key: {:?}", hex::encode(alice.public_key_bytes()));
    println!("Bob public key: {:?}", hex::encode(bob.public_key_bytes()));
    
    // Test ECDH
    let alice_shared = alice.diffie_hellman(bob.public_key());
    let bob_shared = bob.diffie_hellman(alice.public_key());
    
    assert_eq!(alice_shared, bob_shared);
    println!("✅ ECDH key exchange successful!");
    println!("Shared secret: {:?}", hex::encode(alice_shared));
    
    // Test key from bytes
    let test_bytes = [1u8; 32];
    let keypair_from_bytes = X25519KeyPair::from_bytes(test_bytes);
    println!("✅ Key pair creation from bytes successful!");
    println!("Public key from test bytes: {:?}", hex::encode(keypair_from_bytes.public_key_bytes()));
}
