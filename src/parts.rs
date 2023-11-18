//! CryptoURI parts

use crate::{encoding::Encoding, error::Error};
use subtle_encoding::bech32::{self, Bech32};
use zeroize::Zeroize;

/// Parts of a CryptoURI
pub(crate) struct Parts {
    /// CryptoURI prefix
    pub(crate) prefix: String,

    /// Data (i.e. public or private key or key fingerprint)
    pub(crate) data: Vec<u8>,

    /// URI fragment (i.e. comment)
    pub(crate) fragment: Option<String>,
}

impl Parts {
    /// Decode a URI into its prefix (scheme + algorithm), data, and fragment
    pub(crate) fn decode(uri: &str, encoding: &Encoding) -> Result<Self, Error> {
        // Extract the fragment if it exists. Note that fragment is not covered by the
        // bech32 checksum and can be modified (e.g. as a key description)
        if let Some(delimiter) = encoding.fragment_delimiter {
            if let Some(pos) = uri.find(delimiter) {
                let fragment = uri[(pos + 1)..].to_owned();
                let (prefix, data) = Bech32::new(bech32::DEFAULT_CHARSET, encoding.delimiter)
                    .decode(&uri[..pos])
                    .map_err(|_| Error::Parse)?;

                return Ok(Self {
                    prefix,
                    data,
                    fragment: Some(fragment),
                });
            }
        }

        let (prefix, data) = Bech32::new(bech32::DEFAULT_CHARSET, encoding.delimiter)
            .decode(uri)
            .map_err(|_| Error::Parse)?;

        Ok(Self {
            prefix,
            data,
            fragment: None,
        })
    }
}

impl Drop for Parts {
    fn drop(&mut self) {
        self.data.zeroize();
        self.fragment.zeroize();
    }
}
