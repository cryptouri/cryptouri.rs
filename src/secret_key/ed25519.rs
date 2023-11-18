//! The Ed25519 digital signature algorithm

use crate::{algorithm::ED25519_ALG_ID, error::Error};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of an Ed25519 secret key
pub const ED25519_SEC_KEY_SIZE: usize = 32;

/// Ed25519 secret key (i.e. private scalar)
#[derive(Clone)]
pub struct Ed25519SecretKey(Box<[u8; ED25519_SEC_KEY_SIZE]>);

impl AsRef<[u8; ED25519_SEC_KEY_SIZE]> for Ed25519SecretKey {
    fn as_ref(&self) -> &[u8; ED25519_SEC_KEY_SIZE] {
        &self.0
    }
}

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl TryFrom<&[u8]> for Ed25519SecretKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| Ed25519SecretKey(Box::new(bytes)))
            .map_err(|_| Error::Length {
                actual: slice.len(),
                expected: 32,
            })
    }
}

impl ZeroizeOnDrop for Ed25519SecretKey {}

impl_encodable_secret_key!(Ed25519SecretKey, ED25519_ALG_ID);
