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
    // Temporarily rename the signatures dir if it exists
    let dir = Path::new("signatures");
    let mut backup: Option<String> = None;
    if dir.exists() {
        let backup_name = format!("signatures_backup_{}", std::process::id());
        fs::rename(dir, &backup_name).unwrap();
        backup = Some(backup_name);
    }
    sleep(std::time::Duration::from_millis(100)); // Ensure FS settles
    // Should error if signatures dir is missing
    let result = load_signatures();
    assert!(matches!(result, Err(ScanError::Config(_))));

    // Restore the dir if we renamed it
    if let Some(name) = backup {
        let _ = fs::rename(name, dir);
    }
}

#[test]
fn test_load_signatures_valid_and_invalid_files() {
    // Setup a temp signatures dir
    let dir = "signatures";
    let _ = fs::create_dir_all(dir);
    // Valid YAML file
    let valid = "signatures:
  - name: SMTP
    match: SMTP
  - name: SSH
    match: SSH";
    fs::write(format!("{}/valid.yaml", dir), valid).unwrap();
    // Invalid YAML file
    fs::write(format!("{}/invalid.yaml", dir), "not: [valid, yaml").unwrap();
    // Non-YAML file
    fs::write(format!("{}/notyaml.txt", dir), "ignore me").unwrap();
    // Nested dir
    let nested = format!("{}/nested", dir);
    let _ = fs::create_dir_all(&nested);
    fs::write(
        format!("{}/nested/also_valid.yml", dir),
        "signatures:
  - name: FTP
    match: FTP",
    )
    .unwrap();
    // Should load all valid signatures, ignore invalid and non-yaml
    let result = load_signatures();
    assert!(result.is_ok());
    let sigs = result.unwrap();
    let names: Vec<_> = sigs.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"SMTP"));
    assert!(names.contains(&"SSH"));
    assert!(names.contains(&"FTP"));
    // Clean up
    let _ = fs::remove_file(format!("{}/valid.yaml", dir));
    let _ = fs::remove_file(format!("{}/invalid.yaml", dir));
    let _ = fs::remove_file(format!("{}/notyaml.txt", dir));
    let _ = fs::remove_file(format!("{}/nested/also_valid.yml", dir));
    let _ = fs::remove_dir_all(dir);
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
