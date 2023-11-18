//! Error types

use std::fmt::{self, Display};

/// Kinds of errors
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unknown or unsupported algorithm
    Algorithm(String),

    /// Checksum error
    Checksum,

    /// Length error
    Length {
        /// Actual length
        actual: usize,

        /// Expected length
        expected: usize,
    },

    /// parse error
    Parse,

    /// unknown URI scheme
    Scheme(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Algorithm(alg) => write!(f, "algorithm invalid: '{}'", alg),
            Error::Checksum => write!(f, "checksum invalid"),
            Error::Length { expected, actual } => {
                write!(f, "length invalid: {} (expected {})", actual, expected)
            }
            Error::Parse => write!(f, "parse error"),
            Error::Scheme(scheme) => write!(f, "scheme invalid: '{}'", scheme),
        }
    }
}
