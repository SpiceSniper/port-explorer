// Unit tests for config parsing
use port_explorer::config;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;

#[test]
fn test_read_config_valid() {
    let yaml = r#"
    ip: "127.0.0.1"
    start_port: 1
    end_port: 10
    max_threads: 2
    language: "en"
    "#;
    let config: HashMap<String, YamlValue> = serde_yaml::from_str(yaml).unwrap();
    let result = config::get_config(&config);
    assert!(result.is_ok());
    let (_ip, start_port, end_port, max_threads, language) = result.unwrap();
    assert_eq!(start_port, 1);
    assert_eq!(end_port, 10);
    assert_eq!(max_threads, 2);
    assert_eq!(language, "en");
}

#[test]
fn test_missing_ip() {
    let yaml = r#"
    start_port: 1
    end_port: 10
    max_threads: 2
    language: "en"
    "#;
    let config: HashMap<String, YamlValue> = serde_yaml::from_str(yaml).unwrap();
    let result = config::get_config(&config);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("error_ip_not_found") || err.contains("Config error"));
}

#[test]
fn test_invalid_ip() {
    let yaml = r#"
    ip: "not_an_ip"
    start_port: 1
    end_port: 10
    max_threads: 2
    language: "en"
    "#;
    let config: HashMap<String, YamlValue> = serde_yaml::from_str(yaml).unwrap();
    let result = config::get_config(&config);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("error_invalid_ip") || err.contains("Config error"));
}

#[test]
fn test_defaults() {
    // Only ip provided, all else should default
    let yaml = r#"
    ip: "127.0.0.1"
    "#;
    let config: HashMap<String, YamlValue> = serde_yaml::from_str(yaml).unwrap();
    let result = config::get_config(&config);
    assert!(result.is_ok());
    let (_ip, start_port, end_port, max_threads, language) = result.unwrap();
    assert_eq!(start_port, 1);
    assert_eq!(end_port, 65535);
    assert_eq!(max_threads, 100);
    assert_eq!(language, "en");
}

#[test]
fn test_read_config_file_not_found() {
    let result = config::read_config("/this/file/does/not/exist.yaml");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("IO error"));
}

#[test]
fn test_read_config_invalid_yaml() {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "not: [valid, yaml").unwrap(); // broken YAML
    let path = file.path().to_str().unwrap();
    let result = config::read_config(path);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("Config error"));
}