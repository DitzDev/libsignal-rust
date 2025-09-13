# LibSignal Rust

<p align="center">
  <a href="https://crates.io/crates/libsignal-rust">
    <img src="https://img.shields.io/crates/v/libsignal-rust.svg?label=libsignal-rust&color=blue" alt="Crates.io" />
  </a>
  <a href="https://docs.rs/libsignal-rust">
    <img src="https://docs.rs/libsignal-rust/badge.svg" alt="Docs.rs" />
  </a>
  <a href="https://github.com/DitzDev/libsignal-rust/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" />
  </a>
</p>

A complete Rust implementation of the Signal messaging protocol, providing secure end-to-end encryption for messaging applications. This library offers full protocol compatibility with Signal's cryptographic primitives while leveraging Rust's safety and performance benefits.

## Features

- **End-to-End Encryption**: Full Signal protocol implementation with Perfect Forward Secrecy.
- **Double Ratchet Algorithm**: Advanced key management for secure message chains.
- **Industry-Standard Cryptography**: Curve25519 key agreement, Ed25519 signatures, AES-256-CBC encryption, HMAC-SHA256 authentication.
- **Multiple Message Types**: Supports WhisperMessage, PreKeyWhisperMessage, and KeyExchangeMessage.
- **Protocol Buffer Integration**: Complete protobuf serialization/deserialization.
- **Session Management**: Automatic session initialization, key rotation, and state persistence.
- **Memory Safe**: Leverages Rust's ownership model to prevent security vulnerabilities.
- **Zero-Copy Operations**: Efficient message processing with minimal allocations.
- **Async/Await Support**: Modern asynchronous programming patterns throughout.
- **Comprehensive API**: Easy-to-use interfaces for session management and message encryption.
- **Rich Error Handling**: Detailed error types and proper error propagation.
- **Extensive Testing**: Full test coverage for cryptographic, session, and protocol buffer components.

---

## Quick Start

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libsignal-rust = "0.1.0"
```

### Basic Usage

```rust
use libsignal_rust::{SessionCipher, SessionBuilder, ProtocolAddress};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a protocol address for the recipient
    let remote_address = ProtocolAddress::new("alice@example.com".to_string(), 1)?;
    
    // Initialize your storage implementation
    let storage = Arc::new(YourStorageImpl::new());
    
    // Create session cipher for encryption/decryption
    let cipher = SessionCipher::new(storage.clone(), remote_address.clone());
    
    // Encrypt a message
    let plaintext = b"Hello, secure world!";
    let ciphertext_message = cipher.encrypt(plaintext).await?;
    
    println!("Encrypted message type: {}", ciphertext_message.message_type);
    println!("Encrypted body length: {}", ciphertext_message.body.len());
    
    Ok(())
}
```

## Core Components

### SessionCipher

The main interface for encrypting and decrypting messages:

```rust
use libsignal_rust::{SessionCipher, CiphertextMessage};

// Encrypt a message
let message = b"Secret message";
let encrypted: CiphertextMessage = cipher.encrypt(message).await?;

// Decrypt a message  
let decrypted: Vec<u8> = cipher.decrypt(&encrypted).await?;
let original_message = String::from_utf8(decrypted)?;
```

### SessionBuilder

Manages session initialization and key exchange:

```rust
use libsignal_rust::{SessionBuilder, Device, PreKeyBundle, SignedPreKeyBundle};

// Create session builder
let remote_address = ProtocolAddress::new("alice@example.com".to_string(), 1)?;
let builder = SessionBuilder::new(storage, remote_address);

// Initialize outgoing session
let device = Device {
    registration_id: 12345,
    identity_key: identity_key_bytes,
    signed_pre_key: SignedPreKeyBundle {
        key_id: 1,
        public_key: signed_prekey_bytes,
        signature: signature_bytes,
    },
    pre_key: Some(PreKeyBundle {
        key_id: 2,
        public_key: prekey_bytes,
    }),
};

builder.init_outgoing(device).await?;
```

### Key Generation

Generate cryptographic keys for your application:

```rust
use libsignal_rust::{keyhelper, curve};

// Generate identity key pair
let identity_keys = keyhelper::generate_identity_key_pair();

// Generate pre-keys
let pre_key = keyhelper::generate_pre_key(1);
let signed_pre_key = keyhelper::generate_signed_pre_key(&identity_keys, 1)?;

// Generate signing key pair for Ed25519 signatures
let signing_keys = curve::generate_signing_key_pair();
```

## Storage Implementation

Implement the `SessionStorage` trait to provide persistence:

```rust
use libsignal_rust::{SessionStorage, SessionRecord, KeyPair};
use async_trait::async_trait;

pub struct YourStorageImpl {
    // Your storage backend (database, file system, etc.)
}

#[async_trait]
impl SessionStorage for YourStorageImpl {
    async fn is_trusted_identity(&self, address: &str, identity_key: &[u8]) -> bool {
        // Implement identity verification logic
        true
    }
    
    async fn load_session(&self, address: &str) -> Option<SessionRecord> {
        // Load session from your storage backend
        None
    }
    
    async fn store_session(&self, address: &str, record: SessionRecord) {
        // Store session to your storage backend
    }
    
    async fn load_pre_key(&self, pre_key_id: u32) -> Option<KeyPair> {
        // Load pre-key by ID
        None
    }
    
    async fn load_signed_pre_key(&self, signed_pre_key_id: u32) -> Option<KeyPair> {
        // Load signed pre-key by ID  
        None
    }
    
    async fn get_our_identity(&self) -> KeyPair {
        // Return your identity key pair
        KeyPair {
            priv_key: vec![],
            pub_key: vec![],
        }
    }
}
```

## Protocol Buffer Messages

The library uses protocol buffers for message serialization:

```rust
use prost::Message;
use libsignal_rust::protos::{WhisperMessage, PreKeyWhisperMessage};

// Decode a received message
let whisper_msg = WhisperMessage::decode(message_bytes)?;
println!("Message counter: {}", whisper_msg.counter);

// Encode a message for transmission
let encoded = whisper_msg.encode_to_vec();
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test --test crypto_tests      # Cryptographic primitives
cargo test --test curve_tests       # Elliptic curve operations  
cargo test --test session_tests     # Session management
cargo test --test protobuf_tests    # Protocol buffer serialization
```

## Advanced Usage

### Custom Message Processing

```rust
use libsignal_rust::{crypto, curve};

// Direct cryptographic operations
let key = b"32-byte-encryption-key-here!!!!!!";
let iv = b"16-byte-iv-here!"; 
let plaintext = b"Hello World";

let ciphertext = crypto::encrypt(key, plaintext, iv)?;
let decrypted = crypto::decrypt(key, &ciphertext, iv)?;

// ECDH key agreement
let alice_keys = curve::generate_key_pair();
let bob_keys = curve::generate_key_pair();
let shared_secret = curve::calculate_agreement(&bob_keys.pub_key, &alice_keys.priv_key)?;
```

### Error Handling

The library provides detailed error types for different failure scenarios:

```rust
use libsignal_rust::{SessionCipher, errors::*};

match cipher.decrypt(&message).await {
    Ok(plaintext) => println!("Decrypted successfully"),
    Err(e) => match e.downcast_ref::<UntrustedIdentityKeyError>() {
        Some(identity_error) => {
            println!("Untrusted identity: {}", identity_error.addr);
        }
        None => println!("Other error: {}", e),
    }
}
```

## Architecture

### Security Design
- **Memory Safe**: All cryptographic operations use Rust's ownership system to prevent buffer overflows and use-after-free vulnerabilities
- **Constant-Time Operations**: Uses libraries designed to resist timing attacks
- **Forward Secrecy**: Automatic key rotation ensures past messages remain secure even if current keys are compromised

### Protocol Compatibility
- **Signal Protocol v3**: Full compatibility with Signal's current protocol version
- **Cross-Platform**: Generated protocol buffers ensure compatibility with other Signal implementations
- **Standard Cryptography**: Uses widely-audited cryptographic libraries

## Documentation
We will be creating comprehensive and clear documentation soon. For now, check out our documentation on the rust registry.

- [API Documentation](https://docs.rs/libsignal-rust) - Complete API reference

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) and ensure all tests pass:

```bash
cargo fmt
cargo clippy
cargo test
```

## License
```
MIT License

Copyright (c) 2025 DitzDev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```