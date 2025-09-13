use crate::{
    base_key_type::BaseKeyType,
    chain_type::ChainType,
    session_record::{SessionRecord, SessionEntry, CurrentRatchet, IndexInfo, PendingPreKey, ChainInfo, ChainKey},
    crypto,
    curve::{self, KeyPair},
    errors::{UntrustedIdentityKeyError, PreKeyError},
    protocol_address::ProtocolAddress,
    queue_job::queue_job,
};
use std::sync::Arc;

pub trait SessionStorage: Send + Sync {
    fn is_trusted_identity(&self, address: &str, identity_key: &[u8]) -> impl std::future::Future<Output = bool> + Send;
    fn load_session(&self, address: &str) -> impl std::future::Future<Output = Option<SessionRecord>> + Send;
    fn store_session(&self, address: &str, record: SessionRecord) -> impl std::future::Future<Output = ()> + Send;
    fn load_pre_key(&self, pre_key_id: u32) -> impl std::future::Future<Output = Option<KeyPair>> + Send;
    fn load_signed_pre_key(&self, signed_pre_key_id: u32) -> impl std::future::Future<Output = Option<KeyPair>> + Send;
    fn get_our_identity(&self) -> impl std::future::Future<Output = KeyPair> + Send;
}

pub struct Device {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: SignedPreKeyBundle,
    pub pre_key: Option<PreKeyBundle>,
}

pub struct SignedPreKeyBundle {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct PreKeyBundle {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

pub struct PreKeyWhisperMessage {
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: Vec<u8>,
    pub identity_key: Vec<u8>,
    pub message: Vec<u8>,
}

pub struct SessionBuilder<T: SessionStorage> {
    addr: ProtocolAddress,
    storage: Arc<T>,
}

impl<T: SessionStorage + 'static> SessionBuilder<T> {
    pub fn new(storage: Arc<T>, protocol_address: ProtocolAddress) -> Self {
        Self {
            addr: protocol_address,
            storage,
        }
    }

    pub async fn init_outgoing(&self, device: Device) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let storage = self.storage.clone();
        let addr = self.addr.clone();
        
        queue_job(addr.to_string(), async move {
            if !storage.is_trusted_identity(&addr.id, &device.identity_key).await {
                return Err(Box::new(UntrustedIdentityKeyError::new(addr.id.clone(), device.identity_key)) as Box<dyn std::error::Error + Send + Sync>);
            }

            curve::verify_signature(&device.identity_key, &device.signed_pre_key.public_key, &device.signed_pre_key.signature)?;

            let base_key = curve::generate_key_pair();
            let device_pre_key = device.pre_key.as_ref().map(|pk| &pk.public_key);

            let session = Self::static_init_session(
                storage.clone(),
                true,
                Some(&base_key),
                None,
                &device.identity_key,
                device_pre_key.map(|v| &**v),
                Some(&device.signed_pre_key.public_key),
                device.registration_id,
            ).await?;

            let mut session_mut = session.clone();
            session_mut.pending_pre_key = Some(PendingPreKey {
                signed_key_id: device.signed_pre_key.key_id,
                base_key: base_key.pub_key.clone(),
                pre_key_id: device.pre_key.map(|pk| pk.key_id),
            });

            let mut record = storage.load_session(&addr.to_string()).await.unwrap_or_else(|| SessionRecord::new());
            
            if let Some(open_session) = record.get_open_session() {
                let base_key = open_session.index_info.base_key.clone();
                record.close_session(&base_key);
            }

            record.set_session(session_mut);
            storage.store_session(&addr.to_string(), record).await;
            Ok(())
        }).await
    }

    pub async fn init_incoming(&self, record: &mut SessionRecord, message: &PreKeyWhisperMessage) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let fq_addr = self.addr.to_string();
        
        if !self.storage.is_trusted_identity(&fq_addr, &message.identity_key).await {
            return Err(Box::new(UntrustedIdentityKeyError::new(self.addr.id.clone(), message.identity_key.clone())));
        }

        if record.get_session(&message.base_key).is_some() {
            return Ok(None);
        }

        let pre_key_pair = if let Some(pre_key_id) = message.pre_key_id {
            self.storage.load_pre_key(pre_key_id).await
        } else {
            None
        };

        if message.pre_key_id.is_some() && pre_key_pair.is_none() {
            return Err(Box::new(PreKeyError::new("Invalid PreKey ID")));
        }

        let signed_pre_key_pair = self.storage.load_signed_pre_key(message.signed_pre_key_id).await
            .ok_or_else(|| PreKeyError::new("Missing SignedPreKey"))?;

        if let Some(open_session) = record.get_open_session() {
            let base_key = open_session.index_info.base_key.clone();
            record.close_session(&base_key);
        }

        let session = Self::static_init_session(
            self.storage.clone(),
            false,
            pre_key_pair.as_ref(),
            Some(&signed_pre_key_pair),
            &message.identity_key,
            Some(&message.base_key),
            None,
            message.registration_id,
        ).await?;

        record.set_session(session);
        Ok(message.pre_key_id)
    }

    async fn static_init_session<S: SessionStorage>(
        storage: Arc<S>,
        is_initiator: bool,
        our_ephemeral_key: Option<&KeyPair>,
        our_signed_key: Option<&KeyPair>,
        their_identity_pub_key: &[u8],
        their_ephemeral_pub_key: Option<&[u8]>,
        their_signed_pub_key: Option<&[u8]>,
        registration_id: u32,
    ) -> Result<SessionEntry, Box<dyn std::error::Error + Send + Sync>> {
        let our_signed_key = if is_initiator {
            our_ephemeral_key.unwrap()
        } else {
            our_signed_key.unwrap()
        };

        let their_signed_pub_key = if is_initiator {
            their_signed_pub_key.unwrap()
        } else {
            their_ephemeral_pub_key.unwrap()
        };

        let shared_secret_len = if our_ephemeral_key.is_none() || their_ephemeral_pub_key.is_none() {
            32 * 4
        } else {
            32 * 5
        };

        let mut shared_secret = vec![0xffu8; 32];
        shared_secret.resize(shared_secret_len, 0);

        let our_identity = storage.get_our_identity().await;
        let a1 = curve::calculate_agreement(their_signed_pub_key, &our_identity.priv_key)?;
        let a2 = curve::calculate_agreement(their_identity_pub_key, &our_signed_key.priv_key)?;
        let a3 = curve::calculate_agreement(their_signed_pub_key, &our_signed_key.priv_key)?;

        if is_initiator {
            shared_secret[32..64].copy_from_slice(&a1);
            shared_secret[64..96].copy_from_slice(&a2);
        } else {
            shared_secret[64..96].copy_from_slice(&a1);
            shared_secret[32..64].copy_from_slice(&a2);
        }
        shared_secret[96..128].copy_from_slice(&a3);

        if let (Some(our_eph), Some(their_eph)) = (our_ephemeral_key, their_ephemeral_pub_key) {
            let a4 = curve::calculate_agreement(their_eph, &our_eph.priv_key)?;
            shared_secret[128..160].copy_from_slice(&a4);
        }

        let master_key = crypto::derive_secrets(&shared_secret, &[0u8; 32], b"WhisperText", None)?;

        let mut session = SessionEntry::new();
        session.registration_id = registration_id;
        session.current_ratchet = CurrentRatchet {
            root_key: master_key[0].clone(),
            ephemeral_key_pair: if is_initiator { 
                curve::generate_key_pair() 
            } else { 
                our_signed_key.clone() 
            },
            last_remote_ephemeral_key: their_signed_pub_key.to_vec(),
            previous_counter: 0,
        };

        session.index_info = IndexInfo {
            created: chrono::Utc::now().timestamp() as u64,
            used: chrono::Utc::now().timestamp() as u64,
            remote_identity_key: their_identity_pub_key.to_vec(),
            base_key: if is_initiator { 
                our_ephemeral_key.unwrap().pub_key.clone() 
            } else { 
                their_ephemeral_pub_key.unwrap().to_vec() 
            },
            base_key_type: if is_initiator { BaseKeyType::Ours } else { BaseKeyType::Theirs },
            closed: -1,
        };

        if is_initiator {
            let ephemeral_pub_key = session.current_ratchet.ephemeral_key_pair.pub_key.clone();
        session.add_chain(&ephemeral_pub_key, ChainInfo {
                message_keys: Default::default(),
                chain_key: ChainKey {
                    counter: -1,
                    key: Some(master_key[1].clone()),
                },
                chain_type: ChainType::Sending,
            })?;
        }

        Ok(session)
    }
}