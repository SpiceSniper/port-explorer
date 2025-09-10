use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

static LOC_MAP: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Initialise the localisation map from a YAML file for the given language.
/// The file should be located at "resources/localisation/{language}.yaml".
/// It should contain key-value pairs for all localised strings.
///
/// # Arguments
/// * `language` - The language code (e.g., "en", "fr")
///
pub fn init(language: &str) {
    let path = format!("resources/localisation/{}.yaml", language);
    let map = match fs::read_to_string(&path) {
        Ok(content) => {
            serde_yaml::from_str::<HashMap<String, String>>(&content).unwrap_or_default()
        }
        Err(_) => HashMap::new(),
    };
    let mut loc = LOC_MAP.lock().unwrap();
    *loc = map;
}

/// Get a localised string for the given key.
///
///
/// # Arguments
/// * `key` - The localisation key
///
/// # Returns
/// A localised string for the given key. If the key is not found, returns the key itself.
///
pub fn get(key: &str) -> String {
    let loc = LOC_MAP.lock().unwrap();
    loc.get(key).cloned().unwrap_or_else(|| key.to_string())
}
