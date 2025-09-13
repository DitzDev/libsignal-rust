use libsignal_rust::*;

#[test]
fn test_key_pair_generation() {
    let key_pair = generate_key_pair();
    
    // Check key format
    assert_eq!(key_pair.priv_key.len(), 32);
    assert_eq!(key_pair.pub_key.len(), 33);
    assert_eq!(key_pair.pub_key[0], 5); // Version byte
    
    // Generate another key pair and ensure they're different
    let key_pair2 = generate_key_pair();
    assert_ne!(key_pair.priv_key, key_pair2.priv_key);
    assert_ne!(key_pair.pub_key, key_pair2.pub_key);
}

#[test]
fn test_key_agreement() {
    let alice_keys = generate_key_pair();
    let bob_keys = generate_key_pair();
    
    let alice_shared = calculate_agreement(&bob_keys.pub_key, &alice_keys.priv_key)
        .expect("Alice key agreement failed");
    let bob_shared = calculate_agreement(&alice_keys.pub_key, &bob_keys.priv_key)
        .expect("Bob key agreement failed");
    
    assert_eq!(alice_shared, bob_shared);
    assert_eq!(alice_shared.len(), 32);
}

#[test]
fn test_signature_verification() {
    let key_pair = generate_signing_key_pair(); // Use signing key pair for Ed25519 operations
    let message = b"test message for signing";
    
    let signature = calculate_signature(&key_pair.priv_key, message)
        .expect("Signature failed");
    assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
    
    let is_valid = verify_signature(&key_pair.pub_key, message, &signature)
        .expect("Verification failed");
    assert!(is_valid);
    
    // Test with wrong message
    let wrong_message = b"different message";
    let is_valid_wrong = verify_signature(&key_pair.pub_key, wrong_message, &signature)
        .expect("Verification failed");
    assert!(!is_valid_wrong);
}

#[test]
fn test_signature_with_different_keys() {
    let key_pair1 = generate_signing_key_pair(); // Use signing key pairs for Ed25519 operations
    let key_pair2 = generate_signing_key_pair();
    let message = b"test message";
    
    let signature = calculate_signature(&key_pair1.priv_key, message)
        .expect("Signature failed");
    
    // Should fail verification with wrong public key
    let is_valid = verify_signature(&key_pair2.pub_key, message, &signature)
        .expect("Verification failed");
    assert!(!is_valid);
}

#[test]
fn test_key_agreement_consistency() {
    let alice_keys = generate_key_pair();
    let bob_keys = generate_key_pair();
    
    // Multiple computations should yield same result
    let shared1 = calculate_agreement(&bob_keys.pub_key, &alice_keys.priv_key)
        .expect("Key agreement failed");
    let shared2 = calculate_agreement(&bob_keys.pub_key, &alice_keys.priv_key)
        .expect("Key agreement failed");
    
    assert_eq!(shared1, shared2);
}

#[test]
fn test_invalid_key_formats() {
    // Test with invalid private key length
    let result = calculate_agreement(&generate_key_pair().pub_key, &vec![0u8; 16]);
    assert!(result.is_err());
    
    // Test with invalid public key length
    let result = calculate_agreement(&vec![0u8; 16], &generate_key_pair().priv_key);
    assert!(result.is_err());
}