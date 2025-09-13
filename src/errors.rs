use thiserror::Error;

#[derive(Error, Debug)]
#[error("Signal protocol error")]
pub struct SignalError;

#[derive(Error, Debug)]
#[error("Untrusted identity key for address: {addr}")]
pub struct UntrustedIdentityKeyError {
    pub addr: String,
    pub identity_key: Vec<u8>,
}

impl UntrustedIdentityKeyError {
    pub fn new(addr: String, identity_key: Vec<u8>) -> Self {
        Self { addr, identity_key }
    }
}

#[derive(Error, Debug)]
#[error("Session error: {message}")]
pub struct SessionError {
    pub message: String,
}

impl SessionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Error, Debug)]
#[error("Message counter error: {message}")]
pub struct MessageCounterError {
    pub message: String,
}

impl MessageCounterError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Error, Debug)]
#[error("PreKey error: {message}")]
pub struct PreKeyError {
    pub message: String,
}

impl PreKeyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}