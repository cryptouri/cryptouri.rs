//! CryptoURI: URN-like namespace for cryptographic objects (keys, signatures, etc)
//! with Bech32 encoding/checksums

#![doc(
    html_logo_url = "https://avatars3.githubusercontent.com/u/40766087?u=0267cf8b7fe892bbf35b6114d9eb48adc057d6ff",
    html_root_url = "https://docs.rs/cryptouri/0.2.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[macro_use]
mod encoding;
#[macro_use]
pub mod error;

pub mod algorithm;
pub mod hash;
mod parts;
pub mod public_key;
pub mod secret_key;
pub mod signature;

pub use crate::{
    encoding::Encodable,
    error::{Error, ErrorKind},
    hash::Hash,
    public_key::PublicKey,
    secret_key::AsSecretSlice,
    secret_key::SecretKey,
    signature::Signature,
};

use crate::{
    encoding::{Encoding, DASHERIZED_ENCODING, URI_ENCODING},
    parts::Parts,
};

/// `CryptoUri`: URI-based format for encoding cryptographic objects
pub struct CryptoUri {
    /// Kind of `CryptoUri` (e.g. secret key, public key, hashes, signatures)
    kind: CryptoUriKind,

    /// URI fragment (i.e. everything after `#`)
    fragment: Option<String>,
}

/// Kinds of `CryptoUri`s
pub enum CryptoUriKind {
    /// Hashes (i.e. cryptographic digests)
    Hash(Hash),

    /// Public keys (always asymmetric)
    PublicKey(PublicKey),

    /// Secret keys (symmetric or asymmetric)
    SecretKey(SecretKey),

    /// Digital signatures (always asymmetric)
    Signature(Signature),
}

impl CryptoUri {
    /// Parse a `CryptoUri` from a Bech32 encoded string using the given encoding
    // TODO: parser generator rather than handrolling this?
    fn parse(uri: &str, encoding: &Encoding) -> Result<Self, Error> {
        let parts = Parts::decode(uri, encoding)?;

        let kind = if parts.prefix.starts_with(encoding.hash_scheme) {
            CryptoUriKind::Hash(Hash::new(
                &parts.prefix[encoding.hash_scheme.len()..],
                &parts.data,
            )?)
        } else if parts.prefix.starts_with(encoding.public_key_scheme) {
            CryptoUriKind::PublicKey(PublicKey::new(
                &parts.prefix[encoding.public_key_scheme.len()..],
                &parts.data,
            )?)
        } else if parts.prefix.starts_with(encoding.secret_key_scheme) {
            CryptoUriKind::SecretKey(SecretKey::new(
                &parts.prefix[encoding.secret_key_scheme.len()..],
                &parts.data,
            )?)
        } else if parts.prefix.starts_with(encoding.signature_scheme) {
            CryptoUriKind::Signature(Signature::new(
                &parts.prefix[encoding.signature_scheme.len()..],
                &parts.data,
            )?)
        } else {
            fail!(
                ErrorKind::SchemeInvalid,
                "unknown CryptoURI prefix: {}",
                parts.prefix
            )
        };

        Ok(Self {
            kind,
            fragment: parts.fragment.clone(),
        })
    }

    /// Parse a `CryptoUri`
    pub fn parse_uri(uri: &str) -> Result<Self, Error> {
        Self::parse(uri, URI_ENCODING)
    }

    /// Parse a `CryptoUri` in URI-embeddable (a.k.a. "dasherized") encoding
    pub fn parse_dasherized(token: &str) -> Result<Self, Error> {
        Self::parse(token, DASHERIZED_ENCODING)
    }

    /// Return the `CryptoUriKind` for this URI
    pub fn kind(&self) -> &CryptoUriKind {
        &self.kind
    }

    /// Return a `SecretKey` if the underlying URI is a `crypto:sec:key:`
    pub fn secret_key(&self) -> Option<&SecretKey> {
        match self.kind {
            CryptoUriKind::SecretKey(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `CryptoUri` a `crypto:sec:key:`?
    pub fn is_secret_key(&self) -> bool {
        self.secret_key().is_some()
    }

    /// Return a `PublicKey` if the underlying URI is a `crypto:pub:key:`
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self.kind {
            CryptoUriKind::PublicKey(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:pub:key:`?
    pub fn is_public_key(&self) -> bool {
        self.public_key().is_some()
    }

    /// Return a `Digest` if the underlying URI is a `crypto:hash:`
    pub fn hash(&self) -> Option<&Hash> {
        match self.kind {
            CryptoUriKind::Hash(ref hash) => Some(hash),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:hash:`?
    pub fn is_hash(&self) -> bool {
        self.hash().is_some()
    }

    /// Return a `Signature` if the underlying URI is a `crypto:pub:sig:`
    pub fn signature(&self) -> Option<&Signature> {
        match self.kind {
            CryptoUriKind::Signature(ref sig) => Some(sig),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:pub:sig:`?
    pub fn is_signature(&self) -> bool {
        self.signature().is_some()
    }

    /// Obtain the fragment for this URI (i.e. everything after `#`)
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_ref().map(|f| f.as_ref())
    }
}

impl Encodable for CryptoUri {
    /// Serialize this `CryptoUri` as a URI-encoded `String`
    fn to_uri_string(&self) -> String {
        match self.kind {
            CryptoUriKind::Hash(ref hash) => hash.to_uri_string(),
            CryptoUriKind::PublicKey(ref pk) => pk.to_uri_string(),
            CryptoUriKind::SecretKey(ref sk) => sk.to_uri_string(),
            CryptoUriKind::Signature(ref sig) => sig.to_uri_string(),
        }
    }

    /// Serialize this `CryptoUri` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self.kind {
            CryptoUriKind::Hash(ref hash) => hash.to_dasherized_string(),
            CryptoUriKind::PublicKey(ref pk) => pk.to_dasherized_string(),
            CryptoUriKind::SecretKey(ref sk) => sk.to_dasherized_string(),
            CryptoUriKind::Signature(ref sig) => sig.to_dasherized_string(),
        }
    }
}
