//! Digest types

/// NIST SHA-2 family of hash functions
mod sha2;

pub use self::sha2::Sha256Hash;

use crate::algorithm::SHA256_ALG_ID;
use crate::{
    encoding::Encodable,
    error::{Error, ErrorKind},
};
use anomaly::fail;
use std::convert::TryInto;

/// Digest (i.e. hash) algorithms
pub enum Hash {
    /// NIST SHA-2 with a 256-bit digest
    Sha256(Sha256Hash),
}

impl Hash {
    /// Create a new `Digest` for the given algorithm
    pub fn new(alg: &str, bytes: &[u8]) -> Result<Self, Error> {
        let result = match alg {
            SHA256_ALG_ID => Hash::Sha256(bytes.try_into()?),
            _ => fail!(ErrorKind::AlgorithmInvalid, "{}", alg),
        };

        Ok(result)
    }

    /// Return a `Sha256Digest` if the underlying digest is SHA-256
    pub fn sha256_digest(&self) -> Option<&Sha256Hash> {
        match self {
            Hash::Sha256(ref digest) => Some(digest),
        }
    }

    /// Is this Digest a SHA-256 digest?
    pub fn is_sha256_digest(&self) -> bool {
        self.sha256_digest().is_some()
    }
}

impl Encodable for Hash {
    /// Serialize this `Digest` as a URI-encoded `String`
    fn to_uri_string(&self) -> String {
        match self {
            Hash::Sha256(ref digest) => digest.to_uri_string(),
        }
    }

    /// Serialize this `Digest` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self {
            Hash::Sha256(ref digest) => digest.to_dasherized_string(),
        }
    }
}
