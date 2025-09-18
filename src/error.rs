use std::fmt;

/// Custom error type for port explorer
///
#[derive(Debug)]
pub enum ScanError {
    Config(String),
    Io(std::io::Error),
}

/// Display implementation for ScanError
///
impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Config(msg) => write!(f, "Config error: {}", msg),
            ScanError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

/// From implementation to convert std::io::Error into ScanError
///
impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}
