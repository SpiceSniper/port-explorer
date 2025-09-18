#![cfg(test)]

use crate::error::ScanError;
use std::io;

#[test]
fn test_scanerror_config_display() {
    let err = ScanError::Config("bad config".to_string());
    let s = format!("{}", err);
    assert!(s.contains("Config error: bad config"));
}

#[test]
fn test_scanerror_io_display() {
    let io_err = io::Error::new(io::ErrorKind::Other, "fail");
    let err = ScanError::Io(io_err);
    let s = format!("{}", err);
    assert!(s.contains("IO error: fail"));
}

#[test]
fn test_scanerror_from_io() {
    let io_err = io::Error::new(io::ErrorKind::Other, "fail-from");
    let err: ScanError = io_err.into();
    let s = format!("{}", err);
    assert!(matches!(err, ScanError::Io(_)));
    assert!(s.contains("IO error: fail-from"));
}
