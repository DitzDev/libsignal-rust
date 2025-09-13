use cbc::{cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit}};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest};
use subtle::ConstantTimeEq;

type Aes256Cbc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// AES-256-CBC encryption
pub fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".into());
    }

    let cipher = Aes256Cbc::new(key.into(), iv.into());
    Ok(cipher.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(data))
}

/// AES-256-CBC decryption
pub fn decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    if iv.len() != 16 {
        return Err("IV must be 16 bytes".into());
    }

    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    cipher.decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(data)
        .map_err(|e| format!("Decryption error: {:?}", e).into())
}

/// HMAC-SHA256 calculation
pub fn calculate_mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SHA-512 hashing
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculate SHA-512 hash (alias for hash function)
pub fn calculate_sha512(data: &[u8]) -> Vec<u8> {
    hash(data)
}

/// HKDF implementation (RFC 5869) - specific implementation that returns the first 3 32-byte chunks
pub fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8], chunks: Option<usize>) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    if salt.len() != 32 {
        return Err("Got salt of incorrect length".into());
    }

    let chunks = chunks.unwrap_or(3);
    if chunks < 1 || chunks > 3 {
        return Err("Chunks must be between 1 and 3".into());
    }

    let prk = calculate_mac(salt, input);

    let mut results = Vec::new();
    let mut info_array = vec![0u8; info.len() + 1 + 32];
    info_array[32..32 + info.len()].copy_from_slice(info);
    let len = info_array.len();
    info_array[len - 1] = 1;

    let first = calculate_mac(&prk, &info_array[32..]);
    results.push(first.clone());

    if chunks > 1 {
        info_array[..32].copy_from_slice(&first);
        let len = info_array.len();
        info_array[len - 1] = 2;
        let second = calculate_mac(&prk, &info_array[..]);
        results.push(second.clone());

        if chunks > 2 {
            info_array[..32].copy_from_slice(&second);
            let len = info_array.len();
            info_array[len - 1] = 3;
            let third = calculate_mac(&prk, &info_array[..]);
            results.push(third);
        }
    }

    Ok(results)
}

/// Verify HMAC
pub fn verify_mac(data: &[u8], key: &[u8], mac: &[u8], length: usize) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let calculated_mac = calculate_mac(key, data);
    let calculated_mac = &calculated_mac[..length];
    
    if mac.len() != length || calculated_mac.len() != length {
        return Err("Bad MAC length".into());
    }
    
    if calculated_mac.ct_eq(mac).into() {
        Ok(())
    } else {
        Err("Bad MAC".into())
    }
}