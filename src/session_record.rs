use crate::base_key_type::BaseKeyType;
use crate::chain_type::ChainType;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};

const CLOSED_SESSIONS_MAX: usize = 40;
const SESSION_RECORD_VERSION: &str = "v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub message_keys: HashMap<u32, Vec<u8>>,
    pub chain_key: ChainKey,
    pub chain_type: ChainType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainKey {
    pub counter: i32,
    pub key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentRatchet {
    pub ephemeral_key_pair: crate::curve::KeyPair,
    pub last_remote_ephemeral_key: Vec<u8>,
    pub previous_counter: u32,
    pub root_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    pub created: u64,
    pub used: u64,
    pub remote_identity_key: Vec<u8>,
    pub base_key: Vec<u8>,
    pub base_key_type: BaseKeyType,
    pub closed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPreKey {
    pub signed_key_id: u32,
    pub base_key: Vec<u8>,
    pub pre_key_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub registration_id: u32,
    pub current_ratchet: CurrentRatchet,
    pub index_info: IndexInfo,
    pub pending_pre_key: Option<PendingPreKey>,
    chains: HashMap<String, ChainInfo>,
}

impl SessionEntry {
    pub fn new() -> Self {
        Self {
            registration_id: 0,
            current_ratchet: CurrentRatchet {
                ephemeral_key_pair: crate::curve::KeyPair {
                    priv_key: vec![],
                    pub_key: vec![],
                },
                last_remote_ephemeral_key: vec![],
                previous_counter: 0,
                root_key: vec![],
            },
            index_info: IndexInfo {
                created: 0,
                used: 0,
                remote_identity_key: vec![],
                base_key: vec![],
                base_key_type: BaseKeyType::Ours,
                closed: -1,
            },
            pending_pre_key: None,
            chains: HashMap::new(),
        }
    }

    pub fn add_chain(&mut self, key: &[u8], value: ChainInfo) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let id = general_purpose::STANDARD.encode(key);
        if self.chains.contains_key(&id) {
            return Err("Overwrite attempt".into());
        }
        self.chains.insert(id, value);
        Ok(())
    }

    pub fn get_chain(&self, key: &[u8]) -> Option<&ChainInfo> {
        let id = general_purpose::STANDARD.encode(key);
        self.chains.get(&id)
    }

    pub fn get_chain_mut(&mut self, key: &[u8]) -> Option<&mut ChainInfo> {
        let id = general_purpose::STANDARD.encode(key);
        self.chains.get_mut(&id)
    }

    pub fn delete_chain(&mut self, key: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let id = general_purpose::STANDARD.encode(key);
        if !self.chains.contains_key(&id) {
            return Err("Not Found".into());
        }
        self.chains.remove(&id);
        Ok(())
    }

    pub fn chains(&self) -> impl Iterator<Item = (Vec<u8>, &ChainInfo)> {
        self.chains.iter().map(|(k, v)| {
            let key = general_purpose::STANDARD.decode(k).unwrap_or_default();
            (key, v)
        })
    }
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub sessions: HashMap<String, SessionEntry>,
    pub version: String,
}

impl SessionRecord {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            version: SESSION_RECORD_VERSION.to_string(),
        }
    }

    pub fn create_entry() -> SessionEntry {
        SessionEntry::new()
    }

    pub fn have_open_session(&self) -> bool {
        if let Some(open_session) = self.get_open_session() {
            open_session.registration_id > 0
        } else {
            false
        }
    }

    pub fn get_session(&self, key: &[u8]) -> Option<&SessionEntry> {
        let id = general_purpose::STANDARD.encode(key);
        let session = self.sessions.get(&id);
        if let Some(session) = session {
            if session.index_info.base_key_type == BaseKeyType::Ours {
                // Invalid operation cuzz cannot lookup session using our own base key
                return None;
            }
        }
        session
    }

    pub fn get_open_session(&self) -> Option<&SessionEntry> {
        for session in self.sessions.values() {
            if !self.is_closed(session) {
                return Some(session);
            }
        }
        None
    }

    pub fn set_session(&mut self, session: SessionEntry) {
        let id = general_purpose::STANDARD.encode(&session.index_info.base_key);
        self.sessions.insert(id, session);
    }

    pub fn get_sessions(&self) -> Vec<&SessionEntry> {
        let mut sessions: Vec<&SessionEntry> = self.sessions.values().collect();
        sessions.sort_by(|a, b| {
            let a_used = a.index_info.used;
            let b_used = b.index_info.used;
            b_used.cmp(&a_used)
        });
        sessions
    }

    pub fn close_session(&mut self, session_key: &[u8]) {
        let id = general_purpose::STANDARD.encode(session_key);
        if let Some(session) = self.sessions.get_mut(&id) {
            if session.index_info.closed != -1 {
                return;
            }
            session.index_info.closed = chrono::Utc::now().timestamp();
        }
    }

    pub fn open_session(&mut self, session_key: &[u8]) {
        let id = general_purpose::STANDARD.encode(session_key);
        if let Some(session) = self.sessions.get_mut(&id) {
            session.index_info.closed = -1;
        }
    }

    pub fn is_closed(&self, session: &SessionEntry) -> bool {
        session.index_info.closed != -1
    }

    pub fn remove_old_sessions(&mut self) {
        while self.sessions.len() > CLOSED_SESSIONS_MAX {
            let mut oldest_key: Option<String> = None;
            let mut oldest_closed: i64 = i64::MAX;

            for (key, session) in &self.sessions {
                if session.index_info.closed != -1 && session.index_info.closed < oldest_closed {
                    oldest_key = Some(key.clone());
                    oldest_closed = session.index_info.closed;
                }
            }

            if let Some(key) = oldest_key {
                self.sessions.remove(&key);
            } else {
                break;
            }
        }
    }

    pub fn delete_all_sessions(&mut self) {
        self.sessions.clear();
    }
}