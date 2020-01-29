//! Error types

use std::fmt::{self, Display};

/// Error type
#[derive(Clone, Debug)]
pub struct Error {
    /// Kind of error
    kind: ErrorKind,

    /// Optional description message
    msg: Option<String>,
}

impl Error {
    /// Create a new error
    pub fn new(kind: ErrorKind, msg: Option<String>) -> Self {
        Self { kind, msg }
    }

    /// Obtain the `ErrorKind` for this error
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind, None)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.msg {
            Some(ref msg) => write!(f, "{}: {}", &self.kind, msg),
            None => write!(f, "{}", self.kind),
        }
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

impl std::error::Error for Error {}

/// Kinds of errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Unknown or unsupported algorithm
    AlgorithmInvalid,

    /// Checksum error
    ChecksumInvalid,

    /// Error parsing CryptoUri syntax
    ParseError,

    /// Unknown CryptoUri scheme
    SchemeInvalid,
}

impl ErrorKind {
    /// Get a description of this error
    pub fn description(self) -> &'static str {
        match self {
            ErrorKind::AlgorithmInvalid => "unknown or unsupported algorithm",
            ErrorKind::ChecksumInvalid => "checksum error",
            ErrorKind::ParseError => "parse error",
            ErrorKind::SchemeInvalid => "unknown URI scheme",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::error::Error for ErrorKind {}

/// Create a new error (of a given enum variant) with a formatted message
macro_rules! format_err {
    ($kind:path, $msg:expr) => {
        crate::error::Error::new($kind, Some($msg.to_string()))
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        format_err!($kind, format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:path, $msg:expr) => {
        return Err(format_err!($kind, $msg).into());
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, format!($fmt, $($arg)+));
    };
}
