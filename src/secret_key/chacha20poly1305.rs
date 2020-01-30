//! ChaCha20Poly1305 AEAD (RFC 8439)

use crate::{
    algorithm::CHACHA20POLY1305_ALG_ID,
    error::{Error, ErrorKind},
};
use anomaly::format_err;
use secrecy::{DebugSecret, ExposeSecret, Secret};
use std::convert::{TryFrom, TryInto};

/// Size of a ChaCha20Poly1305 key in bytes
pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;

/// ChaCha20Poly1305 encryption key
#[derive(Clone)]
pub struct ChaCha20Poly1305Key(Secret<[u8; CHACHA20POLY1305_KEY_SIZE]>);

impl TryFrom<&[u8]> for ChaCha20Poly1305Key {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| ChaCha20Poly1305Key(Secret::new(bytes)))
            .map_err(|_| {
                format_err!(
                    ErrorKind::ParseError,
                    "bad ChaCha20Poly1305 key: expected 32-bytes, got {}",
                    slice.len(),
                )
                .into()
            })
    }
}

impl DebugSecret for ChaCha20Poly1305Key {}

impl ExposeSecret<[u8; CHACHA20POLY1305_KEY_SIZE]> for ChaCha20Poly1305Key {
    fn expose_secret(&self) -> &[u8; CHACHA20POLY1305_KEY_SIZE] {
        self.0.expose_secret()
    }
}

impl_encodable_secret_key!(ChaCha20Poly1305Key, CHACHA20POLY1305_ALG_ID);
