//! SHA2 hash types

use crate::{algorithm::SHA256_ALG_ID, error::Error};
use std::convert::{TryFrom, TryInto};

/// Size of a SHA-256 hash
pub const SHA256_HASH_SIZE: usize = 32;

/// NIST SHA-256 hashes
pub struct Sha256Hash(pub [u8; SHA256_HASH_SIZE]);

impl TryFrom<&[u8]> for Sha256Hash {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice.try_into().map(Sha256Hash).map_err(|_| Error::Length {
            actual: slice.len(),
            expected: SHA256_HASH_SIZE,
        })
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl_encodable_hash!(Sha256Hash, SHA256_ALG_ID);
