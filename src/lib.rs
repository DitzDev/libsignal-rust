pub mod base_key_type;
pub mod chain_type;
pub mod crypto;
pub mod curve;
pub mod errors;
pub mod keyhelper;
pub mod numeric_fingerprint;
pub mod protocol_address;
pub mod queue_job;
pub mod session_builder;
pub mod session_cipher;
pub mod session_record;
pub mod util;

pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/textsecure.rs"));
}

pub use base_key_type::BaseKeyType;
pub use chain_type::ChainType;
pub use crypto::*;
pub use curve::*;
pub use errors::*;
pub use keyhelper::*;
pub use numeric_fingerprint::FingerprintGenerator;
pub use protocol_address::ProtocolAddress;
pub use queue_job::queue_job;
pub use session_builder::SessionBuilder;
pub use session_cipher::{SessionCipher, CiphertextMessage};
pub use protos::*;
pub use session_record::{SessionRecord, SessionEntry};
pub use util::Util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");