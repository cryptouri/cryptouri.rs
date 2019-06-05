//! The Ed25519 digital signature algorithm

use super::AsSecretSlice;
use crate::{algorithm::ED25519_ALG_ID, error::Error};
use zeroize::Zeroize;

/// Size of an Ed25519 secret key
pub const ED25519_SECKEY_SIZE: usize = 32;

/// Ed25519 secret key (i.e. compressed Edwards-y coordinate)
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Ed25519SecretKey([u8; ED25519_SECKEY_SIZE]);

impl Ed25519SecretKey {
    /// Create a new Ed25519SecretKey object from the given byte array
    /// (containing a randomly chosen secret scalar
    pub fn new(bytes: [u8; ED25519_SECKEY_SIZE]) -> Self {
        Ed25519SecretKey(bytes)
    }

    /// Create a new Ed25519 secret key from a byte slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != ED25519_SECKEY_SIZE {
            fail!(
                ParseError,
                "bad Ed25519 secret key length: {} (expected {})",
                slice.len(),
                ED25519_SECKEY_SIZE
            );
        }

        let mut bytes = [0u8; ED25519_SECKEY_SIZE];
        bytes.copy_from_slice(slice);

        Ok(Self::new(bytes))
    }
}

impl AsSecretSlice for Ed25519SecretKey {
    fn as_secret_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl_encodable_secret_key!(Ed25519SecretKey, ED25519_ALG_ID);
