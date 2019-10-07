//! SHA2 hash types

use crate::{algorithm::SHA256_ALG_ID, error::Error};

/// Size of a SHA-256 hash
pub const SHA256_HASH_SIZE: usize = 32;

/// NIST SHA-256 hashes
pub struct Sha256Hash(pub [u8; SHA256_HASH_SIZE]);

impl Sha256Hash {
    /// Create a new SHA-256 hash
    pub fn new(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != SHA256_HASH_SIZE {
            fail!(
                ParseError,
                "bad SHA-256 hash length: {} (expected {})",
                slice.len(),
                SHA256_HASH_SIZE
            );
        }

        let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
        hash_bytes.copy_from_slice(slice);

        Ok(Sha256Hash(hash_bytes))
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl_encodable_hash!(Sha256Hash, SHA256_ALG_ID);
