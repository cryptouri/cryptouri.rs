//! ChaCha20Poly1305 AEAD (RFC 8439)

use crate::{algorithm::CHACHA20POLY1305_ALG_ID, error::Error};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of a ChaCha20Poly1305 key in bytes
pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;

/// ChaCha20Poly1305 encryption key
#[derive(Clone)]
pub struct ChaCha20Poly1305Key(Box<[u8; CHACHA20POLY1305_KEY_SIZE]>);

impl AsRef<[u8; CHACHA20POLY1305_KEY_SIZE]> for ChaCha20Poly1305Key {
    fn as_ref(&self) -> &[u8; CHACHA20POLY1305_KEY_SIZE] {
        &self.0
    }
}

impl Drop for ChaCha20Poly1305Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl TryFrom<&[u8]> for ChaCha20Poly1305Key {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| ChaCha20Poly1305Key(Box::new(bytes)))
            .map_err(|_| Error::Length {
                actual: slice.len(),
                expected: 32,
            })
    }
}

impl ZeroizeOnDrop for ChaCha20Poly1305Key {}

impl_encodable_secret_key!(ChaCha20Poly1305Key, CHACHA20POLY1305_ALG_ID);
