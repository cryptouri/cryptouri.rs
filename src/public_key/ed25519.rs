//! Ed25519 public keys

use crate::{
    algorithm::ED25519_ALG_ID,
    error::{Error, ErrorKind},
};
use anomaly::format_err;
use std::convert::{TryFrom, TryInto};

/// Size of an Ed25519 public key
pub const ED25519_PUBKEY_SIZE: usize = 32;

/// Ed25519 public key (i.e. compressed Edwards-y coordinate)
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBKEY_SIZE]);

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice.try_into().map(Ed25519PublicKey).map_err(|_| {
            format_err!(
                ErrorKind::ParseError,
                "bad Ed25519 public key length: {} (expected {})",
                slice.len(),
                ED25519_PUBKEY_SIZE
            )
            .into()
        })
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl_encodable_public_key!(Ed25519PublicKey, ED25519_ALG_ID);
