//! Advanced Encryption Standard (AES) keys

// TODO(tarcieri): use a macro, generic-array, or const generics to DRY out 128 vs 256

use crate::{
    algorithm::{AES128GCM_ALG_ID, AES256GCM_ALG_ID},
    error::{Error, ErrorKind},
};
use secrecy::{DebugSecret, ExposeSecret, Secret};
use std::convert::{TryFrom, TryInto};

/// Size of an AES-128 key in bytes
pub const AES128_KEY_SIZE: usize = 16;

/// Size of an AES-256 key in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// AES-128 in Galois/Counter Mode (GCM)
#[derive(Clone)]
pub struct Aes128GcmKey(Secret<[u8; AES128_KEY_SIZE]>);

/// AES-256 in Galois/Counter Mode (GCM)
#[derive(Clone)]
pub struct Aes256GcmKey(Secret<[u8; AES256_KEY_SIZE]>);

impl TryFrom<&[u8]> for Aes128GcmKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| Aes128GcmKey(Secret::new(bytes)))
            .map_err(|_| {
                format_err!(
                    ErrorKind::ParseError,
                    "bad AES-128 key length: {} (expected 16-bytes)",
                    slice.len(),
                )
            })
    }
}

impl TryFrom<&[u8]> for Aes256GcmKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| Aes256GcmKey(Secret::new(bytes)))
            .map_err(|_| {
                format_err!(
                    ErrorKind::ParseError,
                    "bad AES-256 key length: {} (expected 32-bytes)",
                    slice.len(),
                )
            })
    }
}

impl DebugSecret for Aes128GcmKey {}
impl DebugSecret for Aes256GcmKey {}

impl ExposeSecret<[u8; AES128_KEY_SIZE]> for Aes128GcmKey {
    fn expose_secret(&self) -> &[u8; AES128_KEY_SIZE] {
        self.0.expose_secret()
    }
}

impl ExposeSecret<[u8; AES256_KEY_SIZE]> for Aes256GcmKey {
    fn expose_secret(&self) -> &[u8; AES256_KEY_SIZE] {
        self.0.expose_secret()
    }
}

impl_encodable_secret_key!(Aes128GcmKey, AES128GCM_ALG_ID);
impl_encodable_secret_key!(Aes256GcmKey, AES256GCM_ALG_ID);
