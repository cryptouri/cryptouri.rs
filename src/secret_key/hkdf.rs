//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

use super::Algorithm;
use crate::{
    algorithm::HKDFSHA256_ALG_ID,
    encoding::{Encodable, DASHERIZED_ENCODING, URI_ENCODING},
    error::{Error, ErrorKind},
};
use anomaly::{fail, format_err};
use secrecy::{DebugSecret, ExposeSecret, Secret};
use std::convert::{TryFrom, TryInto};

/// Size of an HKDF-SHA-256 secret key
pub const HKDFSHA256_KEY_SIZE: usize = 32;

/// HKDF secret key
#[derive(Clone)]
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

impl Encodable for HkdfSha256Key {
    #[inline]
    fn to_uri_string(&self) -> String {
        let mut alg_id = HKDFSHA256_ALG_ID.to_owned();

        // TODO(tarcieri): generalize serialization for cipher combinations
        if let Some(derived_alg) = &self.derived_alg {
            alg_id = format!("{}+{}", alg_id, derived_alg);
        }

        use subtle_encoding::bech32::{self, Bech32};
        Bech32::new(bech32::DEFAULT_CHARSET, URI_ENCODING.delimiter).encode(
            URI_ENCODING.secret_key_scheme.to_owned() + &alg_id,
            &self.expose_secret()[..],
        )
    }

    #[inline]
    fn to_dasherized_string(&self) -> String {
        let mut alg_id = HKDFSHA256_ALG_ID.to_owned();

        // TODO(tarcieri): generalize serialization for cipher combinations
        if let Some(derived_alg) = &self.derived_alg {
            alg_id = format!("{}_{}", alg_id, derived_alg);
        }

        use subtle_encoding::bech32::{self, Bech32};
        Bech32::new(bech32::DEFAULT_CHARSET, DASHERIZED_ENCODING.delimiter).encode(
            DASHERIZED_ENCODING.secret_key_scheme.to_owned() + &alg_id,
            &self.expose_secret()[..],
        )
    }
}
