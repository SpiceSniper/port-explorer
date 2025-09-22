#![cfg(test)]

use crate::*;
use std::sync::Arc;
use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashMap;

#[test]
fn test_format_duration_hours() {
    let duration = Duration::from_secs(3661); // 1 hour, 1 minute, 1 second
    let result = format_duration(duration);
    assert_eq!(result, "1h 1m 1s");
}

#[test]
fn test_format_duration_minutes() {
    let duration = Duration::from_secs(121); // 2 minutes, 1 second
    let result = format_duration(duration);
    assert_eq!(result, "2m 1s");
}

#[test]
fn test_format_duration_seconds() {
    let duration = Duration::from_millis(1500); // 1.5 seconds
    let result = format_duration(duration);
    assert_eq!(result, "1s 500ms");
}

#[test]
fn test_format_duration_milliseconds() {
    let duration = Duration::from_millis(500);
    let result = format_duration(duration);
    assert_eq!(result, "500ms");
}

#[test]
fn test_format_duration_nanoseconds() {
    let duration = Duration::from_nanos(500);
    let result = format_duration(duration);
    assert_eq!(result, "500ns");
}

#[test]
fn test_scan_port_closed() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    // Port 12345 should be closed on localhost
    let result = scan_port(ip, 12345, signatures);
    assert_eq!(result, None);
}

#[test]
fn test_scan_ports_parallel_empty() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![];
    let pb = indicatif::ProgressBar::new(0);
    let result = scan_ports_parallel(ip, ports, signatures, 1, &pb);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![]);
}

#[test]
fn test_scan_ports_parallel_closed_ports() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![12345, 12346]; // Should be closed
    let pb = indicatif::ProgressBar::new(2);
    let result = scan_ports_parallel(ip, ports, signatures, 2, &pb);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![]);
}

#[test]
fn test_args_struct() {
    // Test that Args can be constructed with all fields None
    let args = Args {
        ip: None,
        start_port: None,
        end_port: None,
        max_threads: None,
        language: None,
    };
    assert!(args.ip.is_none());
    assert!(args.start_port.is_none());
    assert!(args.end_port.is_none());
    assert!(args.max_threads.is_none());
    assert!(args.language.is_none());
}

#[test]
fn test_args_struct_with_values() {
    let args = Args {
        ip: Some("192.168.1.1".to_string()),
        start_port: Some(80),
        end_port: Some(443),
        max_threads: Some(10),
        language: Some("en".to_string()),
    };
    assert_eq!(args.ip, Some("192.168.1.1".to_string()));
    assert_eq!(args.start_port, Some(80));
    assert_eq!(args.end_port, Some(443));
    assert_eq!(args.max_threads, Some(10));
    assert_eq!(args.language, Some("en".to_string()));
}

// Test helper function to create a mock config
fn create_test_config() -> HashMap<String, serde_yaml::Value> {
    let mut config = HashMap::new();
    config.insert("ip".to_string(), serde_yaml::Value::String("127.0.0.1".to_string()));
    config.insert("start_port".to_string(), serde_yaml::Value::Number(1.into()));
    config.insert("end_port".to_string(), serde_yaml::Value::Number(10.into()));
    config.insert("max_threads".to_string(), serde_yaml::Value::Number(2.into()));
    config.insert("language".to_string(), serde_yaml::Value::String("en".to_string()));
    config
}

// Integration test for main function logic (without actually running main)
#[test]
fn test_config_override_logic() {
    let mut config = create_test_config();
    
    // Simulate CLI args overriding config
    let ip_override = "192.168.1.1";
    config.insert("ip".to_string(), serde_yaml::Value::String(ip_override.to_string()));
    
    let start_port_override = 80u16;
    config.insert("start_port".to_string(), serde_yaml::Value::Number(start_port_override.into()));
    
    // Test that the config was properly updated
    assert_eq!(config.get("ip").and_then(|v| v.as_str()), Some(ip_override));
    assert_eq!(config.get("start_port").and_then(|v| v.as_u64()), Some(start_port_override.into()));
}