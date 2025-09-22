#![cfg(test)]

use crate::error::ScanError;
use crate::signatures::*;
use std::fs;
use std::path::Path;
use std::thread::sleep;

#[test]
fn test_identify_service_found() {
    let sigs = vec![Signature {
        name: "HTTP".into(),
        match_: "Server: Apache".into(),
    }];
    let resp = "Server: Apache\r\nContent-Type: text/html";
    assert_eq!(identify_service(resp, &sigs), Some("HTTP".to_string()));
}

#[test]
fn test_identify_service_not_found() {
    let sigs = vec![Signature {
        name: "HTTP".into(),
        match_: "Server: Apache".into(),
    }];
    let resp = "No match here";
    assert_eq!(identify_service(resp, &sigs), None);
}

#[test]
fn test_load_signatures_dir_not_found() {
    // Use tempfile to create an isolated environment without a signatures dir
    let temp_dir = tempfile::tempdir().unwrap();
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(temp_dir.path()).unwrap();
    
    // Should error if signatures dir is missing
    let result = load_signatures();
    
    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
    
    println!("Result: {:?}", result);
    assert!(matches!(result, Err(ScanError::Config(_))));
}

#[test]
fn test_load_signatures_valid_and_invalid_files() {
    // Use tempfile to create a unique test directory
    let temp_dir = tempfile::tempdir().unwrap();
    let signatures_dir = temp_dir.path().join("signatures");
    fs::create_dir_all(&signatures_dir).unwrap();
    
    // Valid YAML file
    let valid = "signatures:
  - name: SMTP
    match: SMTP
  - name: SSH
    match: SSH";
  
    fs::write(signatures_dir.join("valid.yaml"), valid).unwrap();
    
    // Invalid YAML file
    fs::write(signatures_dir.join("invalid.yaml"), "not: [valid, yaml").unwrap();
    
    // Non-YAML file
    fs::write(signatures_dir.join("notyaml.txt"), "ignore me").unwrap();
    
    // Nested dir and file
    let nested_dir = signatures_dir.join("nested");
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(
        nested_dir.join("also_valid.yml"),
        "signatures:
  - name: FTP
    match: FTP",
    ).unwrap();
    
    // Change to the temp directory so load_signatures can find the signatures folder
    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(temp_dir.path()).unwrap();
    
    // Should load all valid signatures, ignore invalid and non-yaml
    let result = load_signatures();
    
    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
    
    println!("Result: {:?}", result);
    if result.is_err() {
        println!("Error: {:?}", result.as_ref().unwrap_err());
    }
    assert!(result.is_ok());
    let sigs = result.unwrap();
    let names: Vec<_> = sigs.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"SMTP"));
    assert!(names.contains(&"SSH"));
    assert!(names.contains(&"FTP"));
    
    // tempfile automatically cleans up
}

#[test]
fn test_extract_signature_from_mapping_variants() {
    use serde_yaml::Mapping;
    use serde_yaml::Value;
    // Only name and match_
    let mut m = Mapping::new();
    m.insert(Value::from("name"), Value::from("HTTP"));
    m.insert(Value::from("match_"), Value::from("Server: Apache"));
    let sig: Option<Signature> = serde_yaml::from_value(Value::Mapping(m.clone())).ok();
    assert!(sig.is_some());
    // Only name and match
    let mut m2 = Mapping::new();
    m2.insert(Value::from("name"), Value::from("SSH"));
    m2.insert(Value::from("match_"), Value::from("SSH"));
    let sig2: Option<Signature> = serde_yaml::from_value(Value::Mapping(m2.clone())).ok();
    assert!(sig2.is_some());
    // Missing fields
    let mut m3 = Mapping::new();
    m3.insert(Value::from("name"), Value::from("FTP"));
    let sig3: Option<Signature> = serde_yaml::from_value(Value::Mapping(m3.clone())).ok();
    assert!(sig3.is_none());
}
