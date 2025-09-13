use libsignal_rust::*;

#[test]
fn test_aes_encryption_decryption() {
    let key = vec![0u8; 32]; // 32-byte key for AES-256
    let iv = vec![0u8; 16];  // 16-byte IV
    let plaintext = b"Hello, Signal Protocol!";
    
    let ciphertext = encrypt(&key, plaintext, &iv).expect("Encryption failed");
    let decrypted = decrypt(&key, &ciphertext, &iv).expect("Decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_hmac_calculation() {
    let key = vec![1u8; 32];
    let data = b"test message";
    
    let mac = calculate_mac(&key, data);
    assert_eq!(mac.len(), 32); // SHA-256 output is 32 bytes
    
    // Test MAC verification
    verify_mac(data, &key, &mac, 32).expect("MAC verification failed");
}

#[test]
fn test_sha512() {
    let data = b"test input";
    let hash = calculate_sha512(data);
    assert_eq!(hash.len(), 64); // SHA-512 output is 64 bytes
    
    // Test deterministic behavior
    let hash2 = calculate_sha512(data);
    assert_eq!(hash, hash2);
}

#[test]
fn test_hkdf_derive_secrets() {
    let input = vec![1u8; 32];
    let salt = vec![2u8; 32];
    let info = b"test info";
    
    let secrets = derive_secrets(&input, &salt, info, Some(3)).expect("HKDF failed");
    assert_eq!(secrets.len(), 3);
    assert_eq!(secrets[0].len(), 32);
    assert_eq!(secrets[1].len(), 32);
    assert_eq!(secrets[2].len(), 32);
    
    // Test that different inputs produce different outputs
    let different_input = vec![3u8; 32];
    let different_secrets = derive_secrets(&different_input, &salt, info, Some(3)).expect("HKDF failed");
    assert_ne!(secrets[0], different_secrets[0]);
}

#[test]
fn test_mac_verification_failure() {
    let key = vec![1u8; 32];
    let data = b"test message";
    let wrong_mac = vec![0u8; 32];
    
    let result = verify_mac(data, &key, &wrong_mac, 32);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let key = (0..32).collect::<Vec<u8>>(); // Sequential bytes as key
    let iv = (16..32).collect::<Vec<u8>>();  // Different sequential bytes as IV
    let original_data = b"This is a longer message to test AES-256-CBC encryption and decryption with PKCS#7 padding.";
    
    let encrypted = encrypt(&key, original_data, &iv).expect("Encryption failed");
    assert_ne!(encrypted, original_data.to_vec());
    
    let decrypted = decrypt(&key, &encrypted, &iv).expect("Decryption failed");
    assert_eq!(original_data.to_vec(), decrypted);
}