//! The Ed25519 digital signature algorithm

use crate::{
    algorithm::ED25519_ALG_ID,
    error::{Error, ErrorKind},
};
use anomaly::format_err;
use secrecy::{DebugSecret, ExposeSecret, Secret};
use std::convert::{TryFrom, TryInto};

/// Size of an Ed25519 secret key
pub const ED25519_SEC_KEY_SIZE: usize = 32;

/// Ed25519 secret key (i.e. private scalar)
#[derive(Clone)]
pub struct Ed25519SecretKey(Secret<[u8; ED25519_SEC_KEY_SIZE]>);

impl TryFrom<&[u8]> for Ed25519SecretKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| Ed25519SecretKey(Secret::new(bytes)))
            .map_err(|_| {
                format_err!(
                    ErrorKind::ParseError,
                    "bad Ed25519 secret key length: {} (expected 32-bytes)",
                    slice.len(),
                )
                .into()
            })
    }
}

impl DebugSecret for Ed25519SecretKey {}

impl ExposeSecret<[u8; ED25519_SEC_KEY_SIZE]> for Ed25519SecretKey {
    fn expose_secret(&self) -> &[u8; ED25519_SEC_KEY_SIZE] {
        self.0.expose_secret()
    }
}

impl_encodable_secret_key!(Ed25519SecretKey, ED25519_ALG_ID);
