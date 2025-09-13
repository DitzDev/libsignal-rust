use crate::crypto::hash;

const VERSION: u16 = 0;

fn iterate_hash(data: &[u8], key: &[u8], count: usize) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(data);
    combined.extend_from_slice(key);
    
    let mut result = hash(&combined);
    
    for _ in 1..count {
        combined.clear();
        combined.extend_from_slice(&result);
        combined.extend_from_slice(key);
        result = hash(&combined);
    }
    
    result
}

fn short_to_bytes(number: u16) -> [u8; 2] {
    number.to_le_bytes()
}

fn get_encoded_chunk(hash: &[u8], offset: usize) -> String {
    let chunk = (hash[offset] as u64) * (1u64 << 32) +
                (hash[offset + 1] as u64) * (1u64 << 24) +
                (hash[offset + 2] as u64) * (1u64 << 16) +
                (hash[offset + 3] as u64) * (1u64 << 8) +
                (hash[offset + 4] as u64);
    
    let chunk = chunk % 100000;
    format!("{:05}", chunk)
}

fn get_display_string_for(identifier: &str, key: &[u8], iterations: usize) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&short_to_bytes(VERSION));
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(identifier.as_bytes());
    
    let output = iterate_hash(&bytes, key, iterations);
    
    get_encoded_chunk(&output, 0) +
        &get_encoded_chunk(&output, 5) +
        &get_encoded_chunk(&output, 10) +
        &get_encoded_chunk(&output, 15) +
        &get_encoded_chunk(&output, 20) +
        &get_encoded_chunk(&output, 25)
}

pub struct FingerprintGenerator {
    iterations: usize,
}

impl FingerprintGenerator {
    pub fn new(iterations: usize) -> Self {
        Self { iterations }
    }

    pub fn create_for(&self, 
                      local_identifier: &str, 
                      local_identity_key: &[u8],
                      remote_identifier: &str, 
                      remote_identity_key: &[u8]) -> String {
        let local_fingerprint = get_display_string_for(local_identifier, local_identity_key, self.iterations);
        let remote_fingerprint = get_display_string_for(remote_identifier, remote_identity_key, self.iterations);
        
        format!("{}{}", local_fingerprint, remote_fingerprint)
    }
}