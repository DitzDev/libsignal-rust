use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyPair {
    pub priv_key: Vec<u8>,
    pub pub_key: Vec<u8>,
}

#[allow(dead_code)]
const PUBLIC_KEY_DER_PREFIX: &[u8] = &[
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
];

#[allow(dead_code)]
const PRIVATE_KEY_DER_PREFIX: &[u8] = &[
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
];

fn validate_priv_key(priv_key: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if priv_key.len() != 32 {
        return Err(format!("Incorrect private key length: {}", priv_key.len()).into());
    }
    Ok(())
}

fn scrub_pub_key_format(pub_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match pub_key.len() {
        33 => {
            // Standard format with version byte 
            // should be 0x05 for curve25519
            if pub_key[0] == 0x05 {
                Ok(pub_key[1..].to_vec())
            } else {
                Err(format!("Invalid public key version byte: expected 0x05, got 0x{:02x}", pub_key[0]).into())
            }
        }
        32 => {
            // Raw 32-byte key format 
            // this is valid but non-standard
            // This is acceptable but indicates the key was generated without a version prefix
            Ok(pub_key.to_vec())
        }
        len => {
            Err(format!("Invalid public key length: expected 32 or 33 bytes, got {} bytes", len).into())
        }
    }
}

/// Generate a new X25519 key pair for ECDH/key agreement
pub fn generate_key_pair() -> KeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    let mut pub_key = vec![5u8];
    pub_key.extend_from_slice(public.as_bytes());
    
    KeyPair {
        priv_key: private.to_bytes().to_vec(),
        pub_key,
    }
}

/// Generate a new Ed25519 key pair for signing/verification
pub fn generate_signing_key_pair() -> KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    let mut pub_key = vec![5u8];
    pub_key.extend_from_slice(verifying_key.as_bytes());
    
    KeyPair {
        priv_key: signing_key.to_bytes().to_vec(),
        pub_key,
    }
}

/// Calculate X25519 key agreement (ECDH)
pub fn calculate_agreement(pub_key: &[u8], priv_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let pub_key_scrubbed = scrub_pub_key_format(pub_key)?;
    validate_priv_key(priv_key)?;
    
    if pub_key_scrubbed.len() != 32 {
        return Err("Invalid public key".into());
    }
    
    let private_key_array: [u8; 32] = priv_key.try_into()
        .map_err(|_| "Private key must be exactly 32 bytes")?;
    let public_key_array: [u8; 32] = pub_key_scrubbed.try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;
    
    let secret = StaticSecret::from(private_key_array);
    let public = PublicKey::from(public_key_array);
    
    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.to_bytes().to_vec())
}

/// Calculate Ed25519 signature
pub fn calculate_signature(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    validate_priv_key(priv_key)?;
    
    if message.is_empty() {
        return Err("Invalid message".into());
    }
    
    let private_key_array: [u8; 32] = priv_key.try_into()
        .map_err(|_| "Private key must be exactly 32 bytes")?;
    
    let signing_key = SigningKey::from_bytes(&private_key_array);
    let signature: Signature = signing_key.sign(message);
    
    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
pub fn verify_signature(pub_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let pub_key_scrubbed = scrub_pub_key_format(pub_key)?;
    
    if pub_key_scrubbed.len() != 32 {
        return Err("Invalid public key".into());
    }
    
    if message.is_empty() {
        return Err("Invalid message".into());
    }
    
    if signature.len() != 64 {
        return Err("Invalid signature".into());
    }
    
    let public_key_array: [u8; 32] = pub_key_scrubbed.try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;
    let signature_array: [u8; 64] = signature.try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;
    
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let sig = Signature::from_bytes(&signature_array);
    
    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}