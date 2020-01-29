//! Secret Key types

/// Advanced Encryption Standard (AES - FIPS 197)
mod aes;

/// Ed25519 elliptic curve digital signature algorithm (RFC 8032)
mod ed25519;

pub use self::{
    aes::{Aes128GcmKey, Aes256GcmKey},
    ed25519::Ed25519SecretKey,
};
pub use secrecy::ExposeSecret;

use crate::{
    algorithm::{AES128GCM_ALG_ID, AES256GCM_ALG_ID, ED25519_ALG_ID},
    encoding::Encodable,
    error::{Error, ErrorKind},
};
use anomaly::fail;
use std::convert::TryInto;

/// Secret key algorithms
pub enum SecretKey {
    /// AES-128 in Galois Counter Mode
    Aes128Gcm(Aes128GcmKey),

    /// AES-256 in Galois Counter Mode
    Aes256Gcm(Aes256GcmKey),

    /// Ed25519 private scalar
    Ed25519(Ed25519SecretKey),
}

impl SecretKey {
    /// Create a new `SecretKey` for the given algorithm
    pub fn new(alg: &str, slice: &[u8]) -> Result<Self, Error> {
        let result = match alg {
            AES128GCM_ALG_ID => SecretKey::Aes128Gcm(slice.try_into()?),
            AES256GCM_ALG_ID => SecretKey::Aes256Gcm(slice.try_into()?),
            ED25519_ALG_ID => SecretKey::Ed25519(slice.try_into()?),
            _ => fail!(ErrorKind::AlgorithmInvalid, "{}", alg),
        };

        Ok(result)
    }

    /// Return an `Aes128GcmKey` if the underlying secret key is AES-128-GCM
    pub fn aes128gcm_key(&self) -> Option<&Aes128GcmKey> {
        match self {
            SecretKey::Aes128Gcm(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an AES-128-GCM secret key?
    pub fn is_aes128gcm_key(&self) -> bool {
        self.aes128gcm_key().is_some()
    }

    /// Return an `Aes256GcmKey` if the underlying secret key is AES-256-GCM
    pub fn aes256gcm_key(&self) -> Option<&Aes256GcmKey> {
        match self {
            SecretKey::Aes256Gcm(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an AES-256-GCM secret key?
    pub fn is_aes256gcm_key(&self) -> bool {
        self.aes256gcm_key().is_some()
    }

    /// Return an `Ed25519SecretKey` if the underlying secret key is Ed25519
    pub fn ed25519_key(&self) -> Option<&Ed25519SecretKey> {
        match self {
            SecretKey::Ed25519(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an Ed25519 secret key?
    pub fn is_ed25519_key(&self) -> bool {
        self.ed25519_key().is_some()
    }
}

impl Encodable for SecretKey {
    /// Serialize this `SecretKey` as a URI-encoded `String`
    fn to_uri_string(&self) -> String {
        match self {
            SecretKey::Aes128Gcm(ref key) => key.to_uri_string(),
            SecretKey::Aes256Gcm(ref key) => key.to_uri_string(),
            SecretKey::Ed25519(ref key) => key.to_uri_string(),
        }
    }

    /// Serialize this `SecretKey` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self {
            SecretKey::Aes128Gcm(ref key) => key.to_uri_string(),
            SecretKey::Aes256Gcm(ref key) => key.to_uri_string(),
            SecretKey::Ed25519(ref key) => key.to_dasherized_string(),
        }
    }
}
