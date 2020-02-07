//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

use super::Algorithm;
use crate::{
    algorithm::HKDFSHA256_ALG_ID,
    error::{Error, ErrorKind},
};
use anomaly::{fail, format_err};
use secrecy::{DebugSecret, ExposeSecret, Secret};
use std::convert::{TryFrom, TryInto};

/// Size of an HKDF-SHA-256 secret key
pub const HKDFSHA256_KEY_SIZE: usize = 32;

/// HKDF secret key
pub struct HkdfSha256Key {
    /// HKDF input key material
    ikm: Secret<[u8; HKDFSHA256_KEY_SIZE]>,

    /// Key type to derive (if specified)
    derived_alg: Option<Algorithm>,
}

impl HkdfSha256Key {
    /// Create a new HKDF-SHA-256 key
    pub fn new(bytes: &[u8], derived_alg: Algorithm) -> Result<Self, Error> {
        if derived_alg == Algorithm::HkdfSha256 {
            fail!(
                ErrorKind::ParseError,
                "invalid algorithm at end of combination: {}",
                derived_alg
            );
        }

        let mut key = Self::try_from(bytes)?;
        key.derived_alg = Some(derived_alg);
        Ok(key)
    }

    /// Get the algorithm for the key to derive (if specified)
    pub fn derived_alg(&self) -> Option<Algorithm> {
        self.derived_alg
    }
}

impl TryFrom<&[u8]> for HkdfSha256Key {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        slice
            .try_into()
            .map(|bytes| HkdfSha256Key {
                ikm: Secret::new(bytes),
                derived_alg: None,
            })
            .map_err(|_| {
                format_err!(
                    ErrorKind::ParseError,
                    "bad HKDF-SHA-256 secret key length: {} (expected 32-bytes)",
                    slice.len(),
                )
                .into()
            })
    }
}

impl DebugSecret for HkdfSha256Key {}

impl ExposeSecret<[u8; HKDFSHA256_KEY_SIZE]> for HkdfSha256Key {
    fn expose_secret(&self) -> &[u8; HKDFSHA256_KEY_SIZE] {
        self.ikm.expose_secret()
    }
}

impl_encodable_secret_key!(HkdfSha256Key, HKDFSHA256_ALG_ID);
