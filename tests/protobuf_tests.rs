use libsignal_rust::*;

#[test]
fn test_protobuf_whisper_message() {
    // Test creating a WhisperMessage with protobuf
    let whisper_msg = protos::WhisperMessage {
        ephemeral_key: vec![1, 2, 3, 4],
        counter: 42,
        previous_counter: 41,
        ciphertext: vec![5, 6, 7, 8, 9],
    };
    
    assert_eq!(whisper_msg.ephemeral_key, vec![1, 2, 3, 4]);
    assert_eq!(whisper_msg.counter, 42);
    assert_eq!(whisper_msg.previous_counter, 41);
    assert_eq!(whisper_msg.ciphertext, vec![5, 6, 7, 8, 9]);
}

#[test]
fn test_protobuf_prekey_whisper_message() {
    // Test creating a PreKeyWhisperMessage with protobuf
    let prekey_msg = protos::PreKeyWhisperMessage {
        registration_id: 123,
        pre_key_id: 456,
        signed_pre_key_id: 789,
        base_key: vec![10, 11, 12],
        identity_key: vec![13, 14, 15],
        message: vec![16, 17, 18],
    };
    
    assert_eq!(prekey_msg.registration_id, 123);
    assert_eq!(prekey_msg.pre_key_id, 456);
    assert_eq!(prekey_msg.signed_pre_key_id, 789);
    assert_eq!(prekey_msg.base_key, vec![10, 11, 12]);
    assert_eq!(prekey_msg.identity_key, vec![13, 14, 15]);
    assert_eq!(prekey_msg.message, vec![16, 17, 18]);
}

#[test]
fn test_protobuf_key_exchange_message() {
    // Test creating a KeyExchangeMessage with protobuf
    let key_exchange = protos::KeyExchangeMessage {
        id: 999,
        base_key: vec![20, 21, 22],
        ephemeral_key: vec![23, 24, 25],
        identity_key: vec![26, 27, 28],
        base_key_signature: vec![29, 30, 31],
    };
    
    assert_eq!(key_exchange.id, 999);
    assert_eq!(key_exchange.base_key, vec![20, 21, 22]);
    assert_eq!(key_exchange.ephemeral_key, vec![23, 24, 25]);
    assert_eq!(key_exchange.identity_key, vec![26, 27, 28]);
    assert_eq!(key_exchange.base_key_signature, vec![29, 30, 31]);
}

#[test]
fn test_protobuf_serialization() {
    use prost::Message;
    
    let whisper_msg = protos::WhisperMessage {
        ephemeral_key: vec![1, 2, 3, 4],
        counter: 42,
        previous_counter: 41,
        ciphertext: vec![5, 6, 7, 8, 9],
    };
    
    // Test encoding
    let encoded = whisper_msg.encode_to_vec();
    assert!(!encoded.is_empty());
    
    // Test decoding
    let decoded = protos::WhisperMessage::decode(&encoded[..])
        .expect("Failed to decode WhisperMessage");
    
    assert_eq!(decoded.ephemeral_key, whisper_msg.ephemeral_key);
    assert_eq!(decoded.counter, whisper_msg.counter);
    assert_eq!(decoded.previous_counter, whisper_msg.previous_counter);
    assert_eq!(decoded.ciphertext, whisper_msg.ciphertext);
}

#[test]
fn test_protobuf_compatibility() {
    use prost::Message;
    let prekey_msg = protos::PreKeyWhisperMessage {
        pre_key_id: 1,          // Field 1 in proto
        base_key: vec![1, 2, 3], // Field 2 in proto
        identity_key: vec![4, 5, 6], // Field 3 in proto
        message: vec![7, 8, 9], // Field 4 in proto (WhisperMessage)
        registration_id: 5,     // Field 5 in proto
        signed_pre_key_id: 6,   // Field 6 in proto
    };
    
    let encoded = prekey_msg.encode_to_vec();
    let decoded = protos::PreKeyWhisperMessage::decode(&encoded[..])
        .expect("Failed to decode PreKeyWhisperMessage");
    
    // Verify field order matches proto definition
    assert_eq!(decoded.pre_key_id, 1);
    assert_eq!(decoded.base_key, vec![1, 2, 3]);
    assert_eq!(decoded.identity_key, vec![4, 5, 6]);
    assert_eq!(decoded.message, vec![7, 8, 9]);
    assert_eq!(decoded.registration_id, 5);
    assert_eq!(decoded.signed_pre_key_id, 6);
}