use crate::curve::{generate_key_pair, calculate_signature, KeyPair};
use rand::Rng;

#[allow(dead_code)]
fn is_non_negative_integer(n: i64) -> bool {
    n >= 0
}

/// Generate identity key pair (same as generate_key_pair)
pub fn generate_identity_key_pair() -> KeyPair {
    generate_key_pair()
}

/// Generate registration ID (14-bit random number)
pub fn generate_registration_id() -> u32 {
    let mut rng = rand::thread_rng();
    let registration_id: u16 = rng.gen();
    (registration_id as u32) & 0x3fff
}

#[derive(Debug, Clone)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub signature: Vec<u8>,
}

/// Generate signed pre-key
pub fn generate_signed_pre_key(identity_key_pair: &KeyPair, signed_key_id: u32) -> Result<SignedPreKey, Box<dyn std::error::Error + Send + Sync>> {
    if identity_key_pair.priv_key.len() != 32 {
        return Err("Invalid argument for identityKeyPair private key".into());
    }
    if identity_key_pair.pub_key.len() != 33 {
        return Err("Invalid argument for identityKeyPair public key".into());
    }
    
    let key_pair = generate_key_pair();
    let signature = calculate_signature(&identity_key_pair.priv_key, &key_pair.pub_key)?;
    
    Ok(SignedPreKey {
        key_id: signed_key_id,
        key_pair,
        signature,
    })
}

#[derive(Debug, Clone)]
pub struct PreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
}

/// Generate pre-key
pub fn generate_pre_key(key_id: u32) -> PreKey {
    let key_pair = generate_key_pair();
    PreKey {
        key_id,
        key_pair,
    }
}