//! Advanced Encryption Standard (AES - FIPS 197) in Galois/Counter Mode

use crate::{
    algorithm::{AES128GCM_ALG_ID, AES256GCM_ALG_ID},
    error::Error,
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

macro_rules! impl_aes_gcm_key {
    ($name:ident, $key_size:expr, $desc:expr) => {
        impl TryFrom<&[u8]> for $name {
            type Error = Error;

            fn try_from(slice: &[u8]) -> Result<Self, Error> {
                slice
                    .try_into()
                    .map(|bytes| $name(Secret::new(bytes)))
                    .map_err(|_| Error::Length {
                        actual: slice.len(),
                        expected: $key_size,
                    })
            }
        }

        impl DebugSecret for $name {}

        impl ExposeSecret<[u8; $key_size]> for $name {
            fn expose_secret(&self) -> &[u8; $key_size] {
                self.0.expose_secret()
            }
        }
    };
}

impl_aes_gcm_key!(Aes128GcmKey, 16, "AES-128-GCM");
impl_aes_gcm_key!(Aes256GcmKey, 32, "AES-128-GCM");

impl_encodable_secret_key!(Aes128GcmKey, AES128GCM_ALG_ID);
impl_encodable_secret_key!(Aes256GcmKey, AES256GCM_ALG_ID);
