//! Cryptographic signatures

/// Ed25519 elliptic curve digital signature algorithm (RFC 8032)
mod ed25519;

pub use self::ed25519::Ed25519Signature;

use crate::{algorithm::ED25519_ALG_ID, encoding::Encodable, error::Error};
use std::convert::TryInto;

/// Signature algorithms
pub enum Signature {
    /// Ed25519 (RFC 8032) signature
    Ed25519(Ed25519Signature),
}

impl Signature {
    /// Create a new `Signature` for the given algorithm
    pub fn new(alg: &str, bytes: &[u8]) -> Result<Self, Error> {
        match alg {
            ED25519_ALG_ID => Ok(Signature::Ed25519(bytes.try_into()?)),
            _ => Err(Error::Algorithm(alg.to_owned())),
        }
    }

    /// Return an `Ed25519Signature` if the underlying signature is Ed25519
    pub fn ed25519_signature(&self) -> Option<&Ed25519Signature> {
        match self {
            Signature::Ed25519(ref sig) => Some(sig),
        }
    }

    /// Is this `Signature` an Ed25519 signature?
    pub fn is_ed25519_signature(&self) -> bool {
        self.ed25519_signature().is_some()
    }
}

impl Encodable for Signature {
    /// Serialize this `Signature` as a URI-encoded `String`
    fn to_uri_string(&self) -> String {
        match self {
            Signature::Ed25519(ref sig) => sig.to_uri_string(),
        }
    }

    /// Serialize this `Signature` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self {
            Signature::Ed25519(ref sig) => sig.to_dasherized_string(),
        }
    }
}
