use crate::{
    chain_type::ChainType,
    session_record::{SessionRecord, SessionEntry, ChainInfo, ChainKey},
    crypto,
    curve,
    errors::{SessionError, MessageCounterError},
    protocol_address::ProtocolAddress,
    queue_job::queue_job,
    session_builder::SessionStorage,
    protos::{WhisperMessage},
};
use std::sync::Arc;

pub struct CiphertextMessage {
    pub message_type: u8,
    pub body: Vec<u8>,
}

pub struct SessionCipher<T: SessionStorage> {
    storage: Arc<T>,
    addr: ProtocolAddress,
}

impl<T: SessionStorage + 'static> SessionCipher<T> {
    pub fn new(storage: Arc<T>, addr: ProtocolAddress) -> Self {
        Self { storage, addr }
    }


    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<CiphertextMessage, Box<dyn std::error::Error + Send + Sync>> {
        let storage = self.storage.clone();
        let addr = self.addr.clone();
        let plaintext = plaintext.to_vec();
        
        queue_job(addr.to_string(), async move {
            let mut record = storage.load_session(&addr.to_string()).await.ok_or("No session record found")?;
            let mut session = record.get_open_session().ok_or("No open session")?.clone();
            
            session.index_info.used = chrono::Utc::now().timestamp() as u64;
            
            let chain_key = session.current_ratchet.ephemeral_key_pair.pub_key.clone();
            let chain = session.get_chain_mut(&chain_key).ok_or("Chain not found")?;
            
            let counter = (chain.chain_key.counter + 1) as u32;
            let message_keys = Self::static_fill_message_keys(chain, counter)?;
            let ciphertext = Self::static_encrypt_message(&message_keys, &plaintext)?;
            
            let whisper_message = WhisperMessage {
                ephemeral_key: session.current_ratchet.ephemeral_key_pair.pub_key.clone(),
                counter: message_keys.counter,
                previous_counter: session.current_ratchet.previous_counter,
                ciphertext,
            };

            let body = Self::static_serialize_whisper_message(&whisper_message)?;
            
            record.set_session(session);
            storage.store_session(&addr.to_string(), record).await;
            
            Ok(CiphertextMessage {
                message_type: 1,
                body,
            })
        }).await
    }

    pub async fn decrypt(&self, ciphertext_message: &CiphertextMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let storage = self.storage.clone();
        let addr = self.addr.clone();
        let message_type = ciphertext_message.message_type;
        let body = ciphertext_message.body.clone();
        
        queue_job(addr.to_string(), async move {
            let mut record = storage.load_session(&addr.to_string()).await.ok_or("No session record found")?;
            
            let plaintext = match message_type {
                1 => Self::static_decrypt_whisper_message(&mut record, &body).await,
                3 => Self::decrypt_pre_key_whisper_message(storage.clone(), addr.clone(), &mut record, &body).await,
                _ => Err("Unknown message type".into()),
            }?;
            
            storage.store_session(&addr.to_string(), record).await;
            
            Ok(plaintext)
        }).await
    }

    async fn static_decrypt_whisper_message(record: &mut SessionRecord, message_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let message = Self::static_deserialize_whisper_message(message_bytes)?;
        let mut session = record.get_open_session().ok_or("No open session")?.clone();

        session.index_info.used = chrono::Utc::now().timestamp() as u64;
        
        Self::static_maybe_step_ratchet(&mut session, &message.ephemeral_key, message.previous_counter)?;
        
        let chain = session.get_chain_mut(&message.ephemeral_key)
            .ok_or("Chain not found")?;
        
        let message_keys = Self::static_fill_message_keys(chain, message.counter)?;
        let plaintext = Self::static_decrypt_message(&message_keys, &message.ciphertext)?;
        
        record.set_session(session);
        // Return the updated record so caller can store it
        // Note (DitzDev): Storage should be handled by the calling function
        
        Ok(plaintext)
    }

    async fn decrypt_pre_key_whisper_message<S: SessionStorage + 'static>(storage: Arc<S>, addr: ProtocolAddress, record: &mut SessionRecord, message_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use prost::Message;
        let prekey_message = crate::protos::PreKeyWhisperMessage::decode(message_bytes)
            .map_err(|e| format!("Failed to decode PreKeyWhisperMessage: {}", e))?;
        
        // Extract the wrapped WhisperMessage
        let whisper_message = crate::protos::WhisperMessage::decode(&prekey_message.message[..])
            .map_err(|e| format!("Failed to decode WhisperMessage: {}", e))?;

        // Check if we already have a session for this PreKey message
        if let Some(session) = record.get_open_session() {
            // Clone the session to avoid borrowing conflicts
            let mut session_clone = session.clone();
            
            // Check if this message matches the pending PreKey
            if let Some(pending) = &session_clone.pending_pre_key {
                if pending.signed_key_id == prekey_message.signed_pre_key_id &&
                   pending.base_key == prekey_message.base_key {
                    // This matches our pending prekey, proceed with decryption
                    session_clone.index_info.used = chrono::Utc::now().timestamp() as u64;
                    
                    Self::static_maybe_step_ratchet(&mut session_clone, &whisper_message.ephemeral_key, whisper_message.previous_counter)?;
                    
                    let chain = session_clone.get_chain_mut(&whisper_message.ephemeral_key)
                        .ok_or("Chain not found")?;
                    
                    let message_keys = Self::static_fill_message_keys(chain, whisper_message.counter)?;
                    let plaintext = Self::static_decrypt_message(&message_keys, &whisper_message.ciphertext)?;
                    
                    // Clear the pending prekey since we've successfully used it
                    session_clone.pending_pre_key = None;
                    record.set_session(session_clone);
                    
                    return Ok(plaintext);
                }
            }
            
            // If we have a session but it doesn't match the PreKey, treat as normal whisper message
            session_clone.index_info.used = chrono::Utc::now().timestamp() as u64;
            
            Self::static_maybe_step_ratchet(&mut session_clone, &whisper_message.ephemeral_key, whisper_message.previous_counter)?;
            
            let chain = session_clone.get_chain_mut(&whisper_message.ephemeral_key)
                .ok_or("Chain not found")?;
            
            let message_keys = Self::static_fill_message_keys(chain, whisper_message.counter)?;
            let plaintext = Self::static_decrypt_message(&message_keys, &whisper_message.ciphertext)?;
            
            record.set_session(session_clone);
            Ok(plaintext)
        } else {
            // No existing session
            // We can use SessionBuilder to create 
            // one from the PreKey message
            use crate::session_builder::{SessionBuilder, PreKeyWhisperMessage as BuilderPreKeyMessage};
            
            // Convert protobuf PreKeyWhisperMessage to SessionBuilder PreKeyWhisperMessage
            let builder_message = BuilderPreKeyMessage {
                registration_id: prekey_message.registration_id,
                pre_key_id: Some(prekey_message.pre_key_id),
                signed_pre_key_id: prekey_message.signed_pre_key_id,
                base_key: prekey_message.base_key.clone(),
                identity_key: prekey_message.identity_key.clone(),
                message: prekey_message.message.clone(),
            };
            
            // Create SessionBuilder and initialize incoming session
            let session_builder = SessionBuilder::new(storage, addr);
            let _pre_key_id = session_builder.init_incoming(record, &builder_message).await?;
            
            // Now that we have a session, proceed with decryption
            if let Some(session) = record.get_open_session() {
                let mut session_clone = session.clone();
                session_clone.index_info.used = chrono::Utc::now().timestamp() as u64;
                
                Self::static_maybe_step_ratchet(&mut session_clone, &whisper_message.ephemeral_key, whisper_message.previous_counter)?;
                
                let chain = session_clone.get_chain_mut(&whisper_message.ephemeral_key)
                    .ok_or("Chain not found")?;
                
                let message_keys = Self::static_fill_message_keys(chain, whisper_message.counter)?;
                let plaintext = Self::static_decrypt_message(&message_keys, &whisper_message.ciphertext)?;
                
                record.set_session(session_clone);
                Ok(plaintext)
            } else {
                Err("Failed to create session from PreKey message".into())
            }
        }
    }
    
    #[allow(dead_code)]
    fn static_get_message_keys(session: &SessionEntry, chain_key: &[u8]) -> Result<MessageKeys, Box<dyn std::error::Error + Send + Sync>> {
        let chain = session.get_chain(chain_key).ok_or("Chain not found")?;
        
        if chain.chain_key.key.is_none() {
            return Err("Chain closed".into());
        }
        
        let key = chain.chain_key.key.as_ref().unwrap();
        let counter = chain.chain_key.counter + 1;
        
        // Use HKDF to derive 80 bytes (32 cipher + 32 mac + 16 IV) just like static_fill_message_keys
        let derived_keys = crypto::derive_secrets(key, &[0u8; 32], b"WhisperMessageKeys", Some(3))
            .map_err(|e| format!("Key derivation error: {}", e))?;
        
        // Concatenate the derived keys: 32 bytes cipher + 32 bytes mac + 16 bytes IV  
        let cipher_key = derived_keys[0].clone();  // 32 bytes cipher key
        let mac_key = derived_keys[1].clone();     // 32 bytes mac key
        let iv = derived_keys[2][..16].to_vec();   // 16 bytes IV
        
        Ok(MessageKeys {
            cipher_key,
            mac_key,
            iv,
            counter: counter as u32,
        })
    }

    fn static_encrypt_message(keys: &MessageKeys, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let ciphertext = crypto::encrypt(&keys.cipher_key, plaintext, &keys.iv)?;
        let mac = crypto::calculate_mac(&keys.mac_key, &ciphertext);
        
        let mut result = ciphertext;
        result.extend_from_slice(&mac[..8]);
        Ok(result)
    }

    fn static_decrypt_message(keys: &MessageKeys, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if ciphertext.len() < 8 {
            return Err("Ciphertext too short".into());
        }
        
        let (message_data, mac) = ciphertext.split_at(ciphertext.len() - 8);
        crypto::verify_mac(message_data, &keys.mac_key, mac, 8)?;
        
        crypto::decrypt(&keys.cipher_key, message_data, &keys.iv)
    }

    fn static_fill_message_keys(chain: &mut ChainInfo, counter: u32) -> Result<MessageKeys, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(message_key) = chain.message_keys.get(&counter) {
            let cipher_key = &message_key[..32];
            let mac_key = &message_key[32..64];
            let iv = &message_key[64..80];
            
            return Ok(MessageKeys {
                cipher_key: cipher_key.to_vec(),
                mac_key: mac_key.to_vec(),
                iv: iv.to_vec(),
                counter,
            });
        }

        if chain.chain_key.counter >= counter as i32 {
            return Err(Box::new(MessageCounterError::new("Message counter too old")));
        }

        if counter as i32 - chain.chain_key.counter > 2000 {
            return Err(Box::new(SessionError::new("Over 2000 messages into the future!")));
        }

        if chain.chain_key.key.is_none() {
            return Err(Box::new(SessionError::new("Chain closed")));
        }

        let mut current_key = chain.chain_key.key.clone().unwrap();
        let mut current_counter = chain.chain_key.counter;

        while current_counter < counter as i32 {
            // Use HKDF to derive 80 bytes (32 cipher + 32 mac + 16 IV)
            let derived_keys = crypto::derive_secrets(&current_key, &[0u8; 32], b"WhisperMessageKeys", Some(3))
                .map_err(|e| format!("Key derivation error: {}", e))?;
            
            // Concatenate the derived keys: 32 bytes cipher + 32 bytes mac + 16 bytes IV
            let mut message_key = Vec::with_capacity(80);
            message_key.extend_from_slice(&derived_keys[0]);  // 32 bytes cipher key
            message_key.extend_from_slice(&derived_keys[1]);  // 32 bytes mac key  
            message_key.extend_from_slice(&derived_keys[2][..16]); // 16 bytes IV
            
            chain.message_keys.insert((current_counter + 1) as u32, message_key);
            current_key = crypto::calculate_mac(&current_key, &[2u8]);
            current_counter += 1;
        }

        chain.chain_key.counter = current_counter;
        chain.chain_key.key = Some(current_key);

        Self::static_fill_message_keys(chain, counter)
    }

    fn static_maybe_step_ratchet(session: &mut SessionEntry, remote_key: &[u8], previous_counter: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if session.get_chain(remote_key).is_some() {
            return Ok(());
        }

        // Clone the key before mutation to avoid borrowing conflicts
        let last_remote = session.current_ratchet.last_remote_ephemeral_key.clone();
        if let Some(previous_ratchet) = session.get_chain_mut(&last_remote) {
            Self::static_fill_message_keys(previous_ratchet, previous_counter)?;
            previous_ratchet.chain_key.key = None; // Close chain
        }

        Self::static_calculate_ratchet(session, remote_key, false)?;

        // Clone the pub key to avoid borrowing conflicts
        let cur_pub = session.current_ratchet.ephemeral_key_pair.pub_key.clone();
        let prev_counter = session.get_chain(&cur_pub)
            .map(|chain| chain.chain_key.counter as u32);

        if let Some(counter) = prev_counter {
            session.current_ratchet.previous_counter = counter;
            session.delete_chain(&cur_pub)?;
        }

        session.current_ratchet.ephemeral_key_pair = curve::generate_key_pair();
        Self::static_calculate_ratchet(session, remote_key, true)?;
        session.current_ratchet.last_remote_ephemeral_key = remote_key.to_vec();

        Ok(())
    }

    fn static_calculate_ratchet(session: &mut SessionEntry, remote_key: &[u8], sending: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Clone needed values to avoid borrowing conflicts
        let root_key = session.current_ratchet.root_key.clone();
        let priv_key = session.current_ratchet.ephemeral_key_pair.priv_key.clone();
        let pub_key = session.current_ratchet.ephemeral_key_pair.pub_key.clone();

        let shared_secret = curve::calculate_agreement(remote_key, &priv_key)?;
        let master_key = crypto::derive_secrets(&shared_secret, &root_key, b"WhisperRatchet", Some(2))?;

        let chain_key = if sending {
            &pub_key
        } else {
            remote_key
        };

        session.add_chain(chain_key, ChainInfo {
            message_keys: Default::default(),
            chain_key: ChainKey {
                counter: -1,
                key: Some(master_key[1].clone()),
            },
            chain_type: if sending { ChainType::Sending } else { ChainType::Receiving },
        })?;

        session.current_ratchet.root_key = master_key[0].clone();
        Ok(())
    }

    fn static_serialize_whisper_message(message: &WhisperMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use prost::Message;
        Ok(message.encode_to_vec())
    }

    fn static_deserialize_whisper_message(data: &[u8]) -> Result<WhisperMessage, Box<dyn std::error::Error + Send + Sync>> {
        use prost::Message;
        WhisperMessage::decode(data)
            .map_err(|e| format!("Failed to decode WhisperMessage: {}", e).into())
    }

    pub async fn has_open_session(&self) -> bool {
        let storage = self.storage.clone();
        let addr = self.addr.clone();
        
        queue_job(addr.to_string(), async move {
            if let Some(record) = storage.load_session(&addr.to_string()).await {
                record.have_open_session()
            } else {
                false
            }
        }).await
    }

    pub async fn close_open_session(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let storage = self.storage.clone();
        let addr = self.addr.clone();
        
        queue_job(addr.to_string(), async move {
            if let Some(mut record) = storage.load_session(&addr.to_string()).await {
                if let Some(open_session) = record.get_open_session() {
                    let base_key = open_session.index_info.base_key.clone();
                    record.close_session(&base_key);
                    storage.store_session(&addr.to_string(), record).await;
                }
            }
            Ok(())
        }).await
    }
}

#[derive(Debug, Clone)]
struct MessageKeys {
    cipher_key: Vec<u8>,
    mac_key: Vec<u8>,
    iv: Vec<u8>,
    counter: u32,
}