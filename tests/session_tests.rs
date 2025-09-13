use libsignal_rust::*;
use libsignal_rust::session_builder::SessionStorage;
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

// Mock storage implementation for testing
#[derive(Clone)]
struct MockStorage {
    sessions: Arc<tokio::sync::Mutex<HashMap<String, SessionRecord>>>,
    identity_keys: Arc<tokio::sync::Mutex<HashMap<String, Vec<u8>>>>,
    pre_keys: Arc<tokio::sync::Mutex<HashMap<u32, KeyPair>>>,
    signed_pre_keys: Arc<tokio::sync::Mutex<HashMap<u32, KeyPair>>>,
    our_identity: KeyPair,
}

impl MockStorage {
    fn new() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            identity_keys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            pre_keys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            signed_pre_keys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            our_identity: generate_key_pair(),
        }
    }
}

#[async_trait]
impl SessionStorage for MockStorage {
    fn is_trusted_identity(&self, _address: &str, _identity_key: &[u8]) -> impl std::future::Future<Output = bool> + Send {
        async { true } // Trust all identities for testing
    }
    
    fn load_session(&self, address: &str) -> impl std::future::Future<Output = Option<SessionRecord>> + Send {
        let sessions = self.sessions.clone();
        let address = address.to_string();
        async move {
            sessions.lock().await.get(&address).cloned()
        }
    }
    
    fn store_session(&self, address: &str, record: SessionRecord) -> impl std::future::Future<Output = ()> + Send {
        let sessions = self.sessions.clone();
        let address = address.to_string();
        async move {
            sessions.lock().await.insert(address, record);
        }
    }
    
    fn load_pre_key(&self, pre_key_id: u32) -> impl std::future::Future<Output = Option<KeyPair>> + Send {
        let pre_keys = self.pre_keys.clone();
        async move {
            pre_keys.lock().await.get(&pre_key_id).cloned()
        }
    }
    
    fn load_signed_pre_key(&self, signed_pre_key_id: u32) -> impl std::future::Future<Output = Option<KeyPair>> + Send {
        let signed_pre_keys = self.signed_pre_keys.clone();
        async move {
            signed_pre_keys.lock().await.get(&signed_pre_key_id).cloned()
        }
    }
    
    fn get_our_identity(&self) -> impl std::future::Future<Output = KeyPair> + Send {
        let identity = self.our_identity.clone();
        async move { identity }
    }
}

#[tokio::test]
async fn test_session_record_creation() {
    let mut record = SessionRecord::new();
    assert!(!record.have_open_session());
    
    let session = SessionRecord::create_entry();
    record.set_session(session);
    // Session would have registration_id > 0 for open session
}

#[tokio::test]
async fn test_session_cipher_creation() {
    let storage = Arc::new(MockStorage::new());
    let address = ProtocolAddress::new("test_user".to_string(), 1).expect("Failed to create address");
    
    let _cipher = SessionCipher::new(storage, address);
    // Just test that it can be created without errors
}

#[test]
fn test_key_helper_functions() {
    let registration_id = generate_registration_id();
    assert!(registration_id > 0);
    
    let identity_keys = generate_identity_key_pair();
    assert_eq!(identity_keys.priv_key.len(), 32);
    assert_eq!(identity_keys.pub_key.len(), 33);
    
    let pre_keys: Vec<_> = (0..10).map(|i| generate_pre_key(i)).collect();
    assert_eq!(pre_keys.len(), 10);
    for (i, pre_key) in pre_keys.iter().enumerate() {
        assert_eq!(pre_key.key_id, i as u32);
        assert_eq!(pre_key.key_pair.pub_key.len(), 33);
    }
    
    let signed_pre_key = generate_signed_pre_key(&identity_keys, 1)
        .expect("Failed to generate signed pre-key");
    assert_eq!(signed_pre_key.key_id, 1);
    assert_eq!(signed_pre_key.signature.len(), 64);
}

#[test]
fn test_protocol_address() {
    let addr = ProtocolAddress::new("alice".to_string(), 1).expect("Failed to create address");
    assert_eq!(addr.id, "alice");
    assert_eq!(addr.device_id, 1);
    
    let addr_str = addr.to_string();
    assert!(addr_str.contains("alice"));
    assert!(addr_str.contains("1"));
    
    let parsed = ProtocolAddress::from_string(&addr_str).expect("Failed to parse address");
    assert_eq!(parsed.id, addr.id);
    assert_eq!(parsed.device_id, addr.device_id);
}

#[test]
fn test_fingerprint_generation() {
    let alice_identity = generate_key_pair();
    let bob_identity = generate_key_pair();
    
    let generator = FingerprintGenerator::new(5200);
    let fingerprint = generator.create_for(
        "alice",
        &alice_identity.pub_key,
        "bob",
        &bob_identity.pub_key,
    );
    
    assert!(!fingerprint.is_empty());
    assert!(fingerprint.len() > 10);
    
    // Test consistency
    let fingerprint2 = generator.create_for(
        "alice",
        &alice_identity.pub_key,
        "bob",
        &bob_identity.pub_key,
    );
    assert_eq!(fingerprint, fingerprint2);
    
    // Test different order gives different result
    let fingerprint3 = generator.create_for(
        "bob",
        &bob_identity.pub_key,
        "alice",
        &alice_identity.pub_key,
    );
    assert_ne!(fingerprint, fingerprint3);
}

#[test]
fn test_error_types() {
    let error = UntrustedIdentityKeyError::new("alice".to_string(), vec![1, 2, 3]);
    assert_eq!(error.addr, "alice");
    assert_eq!(error.identity_key, vec![1, 2, 3]);
    
    let session_error = SessionError::new("test error".to_string());
    assert_eq!(session_error.message, "test error");
}