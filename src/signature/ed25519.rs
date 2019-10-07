//! Ed25519 signatures

use crate::{algorithm::ED25519_ALG_ID, error::Error};
use zeroize::Zeroize;

/// Size of an Ed25519 signature
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Ed25519 signature (i.e. compressed Edwards-y coordinate)
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl Ed25519Signature {
    /// Create a new Ed25519 signature
    pub fn new(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != ED25519_SIGNATURE_SIZE {
            fail!(
                ParseError,
                "bad Ed25519 signature length: {} (expected {})",
                slice.len(),
                ED25519_SIGNATURE_SIZE
            );
        }

        let mut sig_bytes = [0u8; ED25519_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(slice);

        Ok(Ed25519Signature(sig_bytes))
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

// Signatures may be sensitive. Can't hurt (I hope!)
impl Drop for Ed25519Signature {
    fn drop(&mut self) {
        (&mut self.0[..]).zeroize()
    }
}

impl_encodable_signature!(Ed25519Signature, ED25519_ALG_ID);
