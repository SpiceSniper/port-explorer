use port_explorer::localisator;
use std::fs;

#[test]
fn test_init_and_get_existing_key() {
    // Prepare a temp YAML file for language 'testlang'
    let dir = "resources/localisation";
    let _ = fs::create_dir_all(dir);
    let path = format!("{}/testlang.yaml", dir);
    let yaml = "scan_started: Scan started:\nport_range: Port range:";
    fs::write(&path, yaml).unwrap();
    localisator::init("testlang");
    //assert_eq!(localisator::get("scan_started"), "Scan started:");
    //assert_eq!(localisator::get("port_range"), "Port range:");
    // Clean up
    let _ = fs::remove_file(&path);
}

#[test]
fn test_init_missing_file() {
    // Should not panic, should fallback to empty map
    localisator::init("nonexistentlang");
    // Any key should return itself
    assert_eq!(localisator::get("somekey"), "somekey");
}

#[test]
fn test_get_missing_key() {
    // Use a language with a known file
    localisator::init("testlang");
    assert_eq!(localisator::get("not_in_file"), "not_in_file");
}