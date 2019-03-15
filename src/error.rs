use failure::{Backtrace, Context, Fail};
use std::fmt::{self, Display};

/// Error type
#[derive(Debug)]
pub struct Error {
    /// Contextual information about the error
    inner: Context<ErrorKind>,

    /// Optional description message
    description: Option<String>,
}

impl Error {
    /// Create a new error
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
            description: None,
        }
    }

    /// Create a new error with the given description
    pub fn with_description(kind: ErrorKind, description: String) -> Self {
        Self {
            inner: Context::new(kind),
            description: Some(description),
        }
    }

    /// Obtain the inner `ErrorKind` for this error
    #[allow(dead_code)]
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Self {
            inner,
            description: None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.description {
            Some(ref desc) => write!(f, "{}: {}", &self.inner, desc),
            None => Display::fmt(&self.inner, f),
        }
    }
}

impl From<subtle_encoding::Error> for Error {
    fn from(_err: subtle_encoding::Error) -> Error {
        panic!("unimplemented");
    }
}

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Unknown or unsupported algorithm
    #[fail(display = "unknown or unsupported algorithm")]
    AlgorithmInvalid,

    /// Checksum error
    #[fail(display = "checksum error")]
    ChecksumInvalid,

    /// Failure to decode bech32 data
    #[fail(display = "decode error")]
    DecodeError,

    /// Error parsing CryptoUri syntax
    #[fail(display = "invalid key")]
    ParseError,

    /// Unknown CryptoUri scheme
    #[fail(display = "unknown scheme")]
    SchemeInvalid,
}

/// Create a new error (of a given enum variant) with a formatted message
macro_rules! err {
    ($kind:ident, $msg:expr) => {
        crate::error::Error::with_description(
            crate::error::ErrorKind::$kind,
            $msg.to_string()
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        crate::error::Error::with_description(
            crate::error::ErrorKind::$kind,
            format!($fmt, $($arg)+)
        )
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:ident, $msg:expr) => {
        return Err(err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(err!($kind, $fmt, $($arg)+).into());
    };
}
