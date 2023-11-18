//! Ed25519 signatures

use crate::{algorithm::ED25519_ALG_ID, error::Error};
use core::convert::TryFrom;

/// Size of an Ed25519 signature
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Ed25519 signature (i.e. compressed Edwards-y coordinate)
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        // NOTE: Can't use `TryInto` here because `[u8; 64]` doesn't impl
        // `TryFrom<&[u8]>`
        if slice.len() != ED25519_SIGNATURE_SIZE {
            return Err(Error::Length {
                actual: slice.len(),
                expected: ED25519_SIGNATURE_SIZE,
            });
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

impl_encodable_signature!(Ed25519Signature, ED25519_ALG_ID);
