use std::fmt;

/// Errors produced by binutils operations.
#[derive(Debug)]
pub enum BinutilsError {
    /// I/O failure reading or writing an object file.
    Io(std::io::Error),
    /// Not a recognised object/archive format.
    BadFormat(&'static str),
    /// Truncated or malformed archive/object data.
    Malformed(&'static str),
    /// Requested member/symbol/section not found.
    NotFound(String),
}

impl fmt::Display for BinutilsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::BadFormat(m) => write!(f, "bad format: {m}"),
            Self::Malformed(m) => write!(f, "malformed data: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
        }
    }
}

impl std::error::Error for BinutilsError {}
impl From<std::io::Error> for BinutilsError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
