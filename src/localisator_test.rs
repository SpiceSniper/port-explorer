#![cfg(test)]

use crate::localisator;
use std::fs;

#[test]
fn test_init_and_get_existing_key() {
    // Prepare a temp YAML file for language 'testlang'
    let dir = "resources/localisation";
    let _ = fs::create_dir_all(dir);
    let path = format!("{}/testlang.yaml", dir);
    let yaml = "hello: world\nfoo: bar";
    fs::write(&path, yaml).unwrap();
    localisator::init("testlang");
    assert_eq!(localisator::get("hello"), "world");
    assert_eq!(localisator::get("foo"), "bar");
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
