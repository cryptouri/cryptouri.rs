//! CryptoURI encoding support

/// Characters to use when encoding CryptoUris
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Encoding {
    /// Scheme prefix for hashes
    pub hash_scheme: &'static str,

    /// Scheme prefix for public keys
    pub public_key_scheme: &'static str,

    /// Scheme prefix for secret keys
    pub secret_key_scheme: &'static str,

    /// Scheme prefix for signatures
    pub signature_scheme: &'static str,

    /// Bech32 delimiter which separates "Human Readable Part" from binary part
    pub delimiter: char,

    /// Character used to combine disparate primitives into a ciphersuite
    pub combine: char,

    /// Fragment delimiter
    pub fragment_delimiter: Option<char>,
}

// TODO: compute schemes using delimiter rather than hardcoding each one

/// Normal URI encoding
pub(crate) const URI_ENCODING: &Encoding = &Encoding {
    hash_scheme: "crypto:hash:",
    public_key_scheme: "crypto:pub:key:",
    secret_key_scheme: "crypto:sec:key:",
    signature_scheme: "crypto:sig:",
    delimiter: ':',
    combine: '+',
    fragment_delimiter: Some('#'),
};

/// URI-embeddable (a.k.a. "dasherized") encoding
pub(crate) const DASHERIZED_ENCODING: &Encoding = &Encoding {
    hash_scheme: "crypto-hash-",
    public_key_scheme: "crypto-pub-key-",
    secret_key_scheme: "crypto-sec-key-",
    signature_scheme: "crypto-sig-",
    delimiter: '-',
    combine: '_',
    fragment_delimiter: None,
};

/// Objects that can be encoded as CryptoUri
pub trait Encodable {
    /// Encode this object in URI generic syntax
    fn to_uri_string(&self) -> String;

    /// Encode this object in URI-embeddable "dasherized" format
    fn to_dasherized_string(&self) -> String;
}

macro_rules! impl_encodable {
    ($scheme:ident, $name:ident, $alg:expr) => {
        impl crate::encoding::Encodable for $name {
            #[inline]
            fn to_uri_string(&self) -> String {
                use subtle_encoding::bech32::{self, Bech32};
                Bech32::new(
                    bech32::DEFAULT_CHARSET,
                    $crate::encoding::URI_ENCODING.delimiter,
                )
                .encode(
                    $crate::encoding::URI_ENCODING.$scheme.to_owned() + $alg,
                    &self.0[..],
                )
            }

            #[inline]
            fn to_dasherized_string(&self) -> String {
                use subtle_encoding::bech32::{self, Bech32};
                Bech32::new(
                    bech32::DEFAULT_CHARSET,
                    $crate::encoding::DASHERIZED_ENCODING.delimiter,
                )
                .encode(
                    $crate::encoding::DASHERIZED_ENCODING.$scheme.to_owned() + $alg,
                    &self.0[..],
                )
            }
        }
    };
}

macro_rules! impl_encodable_hash {
    ($name:ident, $alg:expr) => {
        impl_encodable!(hash_scheme, $name, $alg);
    };
}

macro_rules! impl_encodable_public_key {
    ($name:ident, $alg:expr) => {
        impl_encodable!(public_key_scheme, $name, $alg);
    };
}

macro_rules! impl_encodable_secret_key {
    ($name:ident, $alg:expr) => {
        impl crate::encoding::Encodable for $name {
            #[inline]
            fn to_uri_string(&self) -> String {
                use subtle_encoding::bech32::{self, Bech32};
                Bech32::new(
                    bech32::DEFAULT_CHARSET,
                    $crate::encoding::URI_ENCODING.delimiter,
                )
                .encode(
                    $crate::encoding::URI_ENCODING.secret_key_scheme.to_owned() + $alg,
                    &self.as_ref()[..],
                )
            }

            #[inline]
            fn to_dasherized_string(&self) -> String {
                use subtle_encoding::bech32::{self, Bech32};
                Bech32::new(
                    bech32::DEFAULT_CHARSET,
                    $crate::encoding::DASHERIZED_ENCODING.delimiter,
                )
                .encode(
                    $crate::encoding::DASHERIZED_ENCODING
                        .secret_key_scheme
                        .to_owned()
                        + $alg,
                    &self.as_ref()[..],
                )
            }
        }
    };
}

macro_rules! impl_encodable_signature {
    ($name:ident, $alg:expr) => {
        impl_encodable!(signature_scheme, $name, $alg);
    };
}
