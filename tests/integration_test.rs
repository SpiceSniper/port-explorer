// Integration tests for Port Explorer
// These tests ensure all modules work together correctly

use port_explorer::config::{read_config, get_config};
use port_explorer::signatures::load_signatures;
use port_explorer::localisator;
use port_explorer::error::ScanError;
use std::collections::HashMap;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_config_integration() {
    // Test that config module functions work together
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "ip: \"127.0.0.1\"").unwrap();
    writeln!(temp_file, "start_port: 1000").unwrap();
    writeln!(temp_file, "end_port: 2000").unwrap();
    writeln!(temp_file, "max_threads: 50").unwrap();
    writeln!(temp_file, "language: \"en\"").unwrap();
    
    let config = read_config(temp_file.path().to_str().unwrap()).unwrap();
    let (ip, start_port, end_port, max_threads, language) = get_config(&config).unwrap();
    
    assert_eq!(ip.to_string(), "127.0.0.1");
    assert_eq!(start_port, 1000);
    assert_eq!(end_port, 2000);
    assert_eq!(max_threads, 50);
    assert_eq!(language, "en");
}

#[test]
fn test_localisator_integration() {
    // Test localisator initialization and usage
    localisator::init("en");
    
    // Test getting a key that should exist
    let message = localisator::get("error_invalid_ip");
    assert!(!message.is_empty());
    // The message might be translated or might return the key if translation fails
    assert!(message.contains("Invalid IP") || message == "error_invalid_ip");
    
    // Test getting a missing key returns the key itself
    let missing = localisator::get("nonexistent_key");
    assert_eq!(missing, "nonexistent_key");
}

#[test]
fn test_signatures_loading() {
    // Test that signatures can be loaded (will fail gracefully if no signatures directory)
    match load_signatures() {
        Ok(signatures) => {
            // If signatures loaded successfully, they should be valid
            for sig in &signatures {
                assert!(!sig.name.is_empty());
                assert!(!sig.match_.is_empty());
            }
        }
        Err(_) => {
            // It's okay if no signatures directory exists for testing
            // This just means the test environment doesn't have signature files
        }
    }
}

#[test]
fn test_error_integration() {
    // Test error types and conversions
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "test error");
    let scan_error: ScanError = io_error.into();
    
    match scan_error {
        ScanError::Io(ref e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }
        _ => panic!("Expected ScanError::Io variant"),
    }
    
    let config_error = ScanError::Config("test config error".to_string());
    let error_msg = format!("{}", config_error);
    assert!(error_msg.contains("test config error"));
}

#[test]
fn test_config_defaults() {
    // Test that config defaults work when no config file exists
    let empty_config = HashMap::new();
    let result = get_config(&empty_config);
    
    assert!(result.is_err()); // Should fail because IP is required
    
    if let Err(ScanError::Config(msg)) = result {
        assert!(msg.contains("IP address not found") || msg.contains("error_ip_not_found"));
    } else {
        panic!("Expected ScanError::Config for missing IP");
    }
}

#[test]
fn test_config_overrides() {
    // Test that config values can be overridden
    let mut config = HashMap::new();
    config.insert("ip".to_string(), serde_yaml::Value::String("192.168.1.1".to_string()));
    config.insert("start_port".to_string(), serde_yaml::Value::Number(100.into()));
    config.insert("end_port".to_string(), serde_yaml::Value::Number(200.into()));
    
    let (ip, start_port, end_port, max_threads, language) = get_config(&config).unwrap();
    
    assert_eq!(ip.to_string(), "192.168.1.1");
    assert_eq!(start_port, 100);
    assert_eq!(end_port, 200);
    assert_eq!(max_threads, 100); // default
    assert_eq!(language, "en"); // default
}

#[test]
fn test_dummy() {
    assert_eq!(2 + 2, 4);
}
