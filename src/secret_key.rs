//! Secret Key types

mod aesgcm;
mod chacha20poly1305;
mod ed25519;
mod hkdf;

pub use self::{
    aesgcm::{Aes128GcmKey, Aes256GcmKey},
    chacha20poly1305::ChaCha20Poly1305Key,
    ed25519::Ed25519SecretKey,
    hkdf::HkdfSha256Key,
};
pub use secrecy::ExposeSecret;

use crate::{
    algorithm::{
        AES128GCM_ALG_ID, AES256GCM_ALG_ID, CHACHA20POLY1305_ALG_ID, ED25519_ALG_ID,
        HKDFSHA256_ALG_ID,
    },
    encoding::Encodable,
    error::{Error, ErrorKind},
};
use anomaly::fail;
use std::{
    convert::TryInto,
    fmt::{self, Display},
    str::FromStr,
};

/// Secret key algorithms
// TODO(tarcieri): factor these apart by algorithm category (AEADs, KDFs, signature etc)
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Algorithm {
    /// AES-128 in Galois/Counter Mode
    Aes128Gcm,

    /// AES-256 in Galois/Counter Mode
    Aes256Gcm,

    /// ChaCha20Poly1305 AEAD
    ChaCha20Poly1305,

    /// Ed25519
    Ed25519,

    /// HKDF (RFC 5869) instantiated with HMAC-SHA-256
    HkdfSha256,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Algorithm::Aes128Gcm => AES128GCM_ALG_ID,
            Algorithm::Aes256Gcm => AES256GCM_ALG_ID,
            Algorithm::ChaCha20Poly1305 => CHACHA20POLY1305_ALG_ID,
            Algorithm::Ed25519 => ED25519_ALG_ID,
            Algorithm::HkdfSha256 => HKDFSHA256_ALG_ID,
        })
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            AES128GCM_ALG_ID => Algorithm::Aes128Gcm,
            AES256GCM_ALG_ID => Algorithm::Aes256Gcm,
            CHACHA20POLY1305_ALG_ID => Algorithm::ChaCha20Poly1305,
            ED25519_ALG_ID => Algorithm::Ed25519,
            HKDFSHA256_ALG_ID => Algorithm::HkdfSha256,
            _ => fail!(ErrorKind::ParseError, "invalid secret key algorithm: {}", s),
        })
    }
}

/// Secret key types
pub enum SecretKey {
    /// AES-128 in Galois/Counter Mode
    Aes128Gcm(Aes128GcmKey),

    /// AES-256 in Galois/Counter Mode
    Aes256Gcm(Aes256GcmKey),

    /// ChaCha20Poly1305 AEAD
    ChaCha20Poly1305(ChaCha20Poly1305Key),

    /// Ed25519 private scalar
    Ed25519(Ed25519SecretKey),

    /// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    /// instantiated with HMAC-SHA-256
    HkdfSha256(HkdfSha256Key),
}

impl SecretKey {
    /// Create a new `SecretKey` for the given algorithm
    pub fn new(alg: &str, slice: &[u8]) -> Result<Self, Error> {
        let result = match alg {
            AES128GCM_ALG_ID => SecretKey::Aes128Gcm(slice.try_into()?),
            AES256GCM_ALG_ID => SecretKey::Aes256Gcm(slice.try_into()?),
            CHACHA20POLY1305_ALG_ID => SecretKey::ChaCha20Poly1305(slice.try_into()?),
            ED25519_ALG_ID => SecretKey::Ed25519(slice.try_into()?),
            HKDFSHA256_ALG_ID => SecretKey::HkdfSha256(slice.try_into()?),
            _ => fail!(ErrorKind::AlgorithmInvalid, "{}", alg),
        };

        Ok(result)
    }

    /// Create a new `SecretKey` which combines multiple algorithms
    pub fn new_combination(algs: &[&str], slice: &[u8]) -> Result<Self, Error> {
        if algs.len() != 2 {
            fail!(
                ErrorKind::ParseError,
                "can't combine more than two algorithms: {}",
                algs.join(",")
            );
        }

        // TODO(tarcieri): support other key derivation algorithms besides HKDF-SHA-256
        if algs[0] != HKDFSHA256_ALG_ID {
            fail!(
                ErrorKind::ParseError,
                "invalid algorithm at start of combination: {}",
                algs[0]
            );
        }

        let key = HkdfSha256Key::new(slice, algs[1].parse()?)?;
        Ok(SecretKey::HkdfSha256(key))
    }

    /// Return an `Aes128GcmKey` if the underlying secret key is AES-128-GCM
    pub fn aes128gcm_key(&self) -> Option<&Aes128GcmKey> {
        match self {
            SecretKey::Aes128Gcm(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an AES-128-GCM secret key?
    pub fn is_aes128gcm_key(&self) -> bool {
        self.aes128gcm_key().is_some()
    }

    /// Return an `Aes256GcmKey` if the underlying secret key is AES-256-GCM
    pub fn aes256gcm_key(&self) -> Option<&Aes256GcmKey> {
        match self {
            SecretKey::Aes256Gcm(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an AES-256-GCM secret key?
    pub fn is_aes256gcm_key(&self) -> bool {
        self.aes256gcm_key().is_some()
    }

    /// Return an `Ed25519SecretKey` if the underlying secret key is Ed25519
    pub fn ed25519_key(&self) -> Option<&Ed25519SecretKey> {
        match self {
            SecretKey::Ed25519(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an Ed25519 secret key?
    pub fn is_ed25519_key(&self) -> bool {
        self.ed25519_key().is_some()
    }

    /// Return an `HkdfSha256Key` if the underlying secret key is HKDF-SHA-256
    pub fn hkdfsha256_key(&self) -> Option<&HkdfSha256Key> {
        match self {
            SecretKey::HkdfSha256(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `SecretKey` an Ed25519 secret key?
    pub fn is_hkdfsha256_key(&self) -> bool {
        self.hkdfsha256_key().is_some()
    }
}

impl Encodable for SecretKey {
    /// Serialize this `SecretKey` as a URI-encoded `String`
    fn to_uri_string(&self) -> String {
        match self {
            SecretKey::Aes128Gcm(ref key) => key.to_uri_string(),
            SecretKey::Aes256Gcm(ref key) => key.to_uri_string(),
            SecretKey::ChaCha20Poly1305(ref key) => key.to_uri_string(),
            SecretKey::Ed25519(ref key) => key.to_uri_string(),
            SecretKey::HkdfSha256(ref key) => key.to_uri_string(),
        }
    }

    /// Serialize this `SecretKey` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self {
            SecretKey::Aes128Gcm(ref key) => key.to_dasherized_string(),
            SecretKey::Aes256Gcm(ref key) => key.to_dasherized_string(),
            SecretKey::ChaCha20Poly1305(ref key) => key.to_dasherized_string(),
            SecretKey::Ed25519(ref key) => key.to_dasherized_string(),
            SecretKey::HkdfSha256(ref key) => key.to_dasherized_string(),
        }
    }
}
