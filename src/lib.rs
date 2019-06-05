//! CryptoURI: URN-like namespace for cryptographic objects (keys, signatures, etc)
//! with Bech32 encoding/checksums

#![crate_name = "cryptouri"]
#![crate_type = "rlib"]
#![deny(warnings, missing_docs, unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]
#![doc(
    html_logo_url = "https://avatars3.githubusercontent.com/u/40766087?u=0267cf8b7fe892bbf35b6114d9eb48adc057d6ff",
    html_root_url = "https://docs.rs/cryptouri/0.1.1"
)]

#[macro_use]
mod encoding;
#[macro_use]
pub mod error;

pub mod algorithm;
pub mod digest;
mod parts;
pub mod public_key;
pub mod secret_key;
pub mod signature;

pub use crate::{encoding::Encodable, secret_key::AsSecretSlice};

use crate::{
    digest::Digest,
    encoding::{Encoding, DASHERIZED_ENCODING, URI_ENCODING},
    error::Error,
    parts::Parts,
    public_key::PublicKey,
    secret_key::SecretKey,
    signature::Signature,
};

/// `CryptoUri`: URI-based format for encoding cryptographic objects
pub struct CryptoUri {
    /// Kind of `CryptoUri` (e.g. secret key, public key, digests, signatures)
    kind: CryptoUriKind,

    /// URI fragment (i.e. everything after `#`)
    fragment: Option<String>,
}

/// Kinds of `CryptoUri`s
pub enum CryptoUriKind {
    /// Digests (e.g. key digests symmetric secret keys, asymmetric public keys, or other data)
    Digest(Digest),

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

        let kind = if parts.prefix.starts_with(encoding.digest_scheme) {
            CryptoUriKind::Digest(Digest::new(
                &parts.prefix[encoding.digest_scheme.len()..],
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
            fail!(SchemeInvalid, "unknown CryptoURI prefix: {}", parts.prefix)
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

    /// Return a `SecretKey` if the underlying URI is a `crypto:secret:key:`
    pub fn secret_key(&self) -> Option<&SecretKey> {
        match self.kind {
            CryptoUriKind::SecretKey(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this `CryptoUri` a `crypto:secret:key:`?
    pub fn is_secret_key(&self) -> bool {
        self.secret_key().is_some()
    }

    /// Return a `PublicKey` if the underlying URI is a `crypto:public:key:`
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self.kind {
            CryptoUriKind::PublicKey(ref key) => Some(key),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:public:key:`?
    pub fn is_public_key(&self) -> bool {
        self.public_key().is_some()
    }

    /// Return a `Digest` if the underlying URI is a `crypto:public:digest:`
    pub fn digest(&self) -> Option<&Digest> {
        match self.kind {
            CryptoUriKind::Digest(ref digest) => Some(digest),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:public:digest:`?
    pub fn is_digest(&self) -> bool {
        self.digest().is_some()
    }

    /// Return a `Signature` if the underlying URI is a `crypto:public:signature:`
    pub fn signature(&self) -> Option<&Signature> {
        match self.kind {
            CryptoUriKind::Signature(ref sig) => Some(sig),
            _ => None,
        }
    }

    /// Is this CryptoUri a `crypto:public:signature:`?
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
            CryptoUriKind::Digest(ref digest) => digest.to_uri_string(),
            CryptoUriKind::PublicKey(ref pk) => pk.to_uri_string(),
            CryptoUriKind::SecretKey(ref sk) => sk.to_uri_string(),
            CryptoUriKind::Signature(ref sig) => sig.to_uri_string(),
        }
    }

    /// Serialize this `CryptoUri` as a "dasherized" `String`
    fn to_dasherized_string(&self) -> String {
        match self.kind {
            CryptoUriKind::Digest(ref digest) => digest.to_dasherized_string(),
            CryptoUriKind::PublicKey(ref pk) => pk.to_dasherized_string(),
            CryptoUriKind::SecretKey(ref sk) => sk.to_dasherized_string(),
            CryptoUriKind::Signature(ref sig) => sig.to_dasherized_string(),
        }
    }
}
