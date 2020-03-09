//! Error types

use anomaly::{BoxError, Context};
use displaydoc::Display;
use std::{
    fmt::{self, Display},
    ops::Deref,
};

/// Kinds of errors
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub enum ErrorKind {
    /// unknown or unsupported algorithm
    AlgorithmInvalid,

    /// checksum error
    ChecksumInvalid,

    /// parse error
    ParseError,

    /// unknown URI scheme
    SchemeInvalid,
}

impl ErrorKind {
    /// Add context to an [`ErrorKind`]
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl std::error::Error for ErrorKind {}

/// Error type
#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Deref for Error {
    type Target = Context<ErrorKind>;

    fn deref(&self) -> &Context<ErrorKind> {
        &self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Context::new(kind, None).into()
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(context: Context<ErrorKind>) -> Self {
        Error(Box::new(context))
    }
}

impl From<subtle_encoding::Error> for Error {
    fn from(err: subtle_encoding::Error) -> Error {
        match err {
            subtle_encoding::Error::ChecksumInvalid => ErrorKind::ChecksumInvalid,
            _ => ErrorKind::ParseError,
        }
        .into()
    }
}
