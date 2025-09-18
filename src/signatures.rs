use crate::error::ScanError;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;
use std::path::Path;

/// Represents a service signature with a name and a matching string.
///
/// # Fields
/// * `name` - The name of the service (e.g., "HTTP", "FTP").
/// * `match_` - A substring to match in the response to identify the service
///
#[derive(Debug, Deserialize, Clone)]
pub struct Signature {
    pub name: String,
    pub match_: String,
}

/// Identify the service based on response content and known signatures.
///
/// # Arguments
/// * `response` - The response string from the scanned port.
/// * `signatures` - A slice of known service signatures.
///
/// # Returns
/// * `Some(String)` - The name of the identified service, if a matching signature is found.
/// * `None` - If no matching signature is found.
///
pub fn identify_service(response: &str, signatures: &[Signature]) -> Option<String> {
    for sig in signatures {
        if response.contains(&sig.match_) {
            return Some(sig.name.clone());
        }
    }
    None
}

/// Load signatures from YAML files in the "signatures" directory and its subdirectories.
///
/// Returns
/// * `Ok(Vec<Signature>)` - A vector of loaded signatures.
/// * `Err(ScanError)` - If there was an error reading or parsing the signature files.
///
/// Returns
/// * `Ok(Vec<Signature>)` - A vector of loaded signatures.
/// * `Err(ScanError)` - If there was an error reading or parsing the signature files.
///
pub fn load_signatures() -> Result<Vec<Signature>, ScanError> {
    /// Check if a file has a .yml or .yaml extension.
    ///
    /// # Arguments
    /// * `path` - A reference to a Path to check.
    ///
    /// # Returns
    /// * `true` - If the file has a .yml or .yaml extension.
    /// * `false` - Otherwise.
    ///
    fn is_yaml_file(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
    }

    /// Extract a Signature from a YAML mapping.
    ///
    /// # Arguments
    /// * `m` - A reference to a serde_yaml::Mapping representing a signature.
    ///
    /// # Returns
    /// * `Some(Signature)` - If the mapping contains valid fields.
    /// * `None` - If the mapping is missing required fields.
    ///
    fn extract_signature_from_mapping(m: &serde_yaml::Mapping) -> Option<Signature> {
        let name = m.get(&YamlValue::from("name")).and_then(|v| v.as_str());
        let match_str = m
            .get(&YamlValue::from("match_"))
            .and_then(|v| v.as_str())
            .or_else(|| m.get(&YamlValue::from("match")).and_then(|v| v.as_str()));

        match (name, match_str) {
            (Some(n), Some(ms)) => Some(Signature {
                name: n.to_string(),
                match_: ms.to_string(),
            }),
            _ => None,
        }
    }

    /// Process a YAML mapping to extract signatures.
    ///
    /// # Arguments
    /// * `map` - A reference to a serde_yaml::Mapping.
    /// * `out` - A mutable reference to a vector to collect signatures.
    ///
    /// # Returns
    /// * `None` - If the mapping is missing the "signatures" key.
    ///
    fn process_mapping(map: &serde_yaml::Mapping, out: &mut Vec<Signature>) {
        if let Some(seq) = map
            .get(&YamlValue::from("signatures"))
            .and_then(|v| v.as_sequence())
        {
            for item in seq {
                if let Some(m) = item.as_mapping() {
                    if let Some(sig) = extract_signature_from_mapping(m) {
                        out.push(sig);
                    }
                }
            }
            return;
        }

        // Fallback: treat mapping as { name: match } pairs
        for (k, v) in map {
            if let (Some(name), Some(ms)) = (k.as_str(), v.as_str()) {
                out.push(Signature {
                    name: name.to_string(),
                    match_: ms.to_string(),
                });
            }
        }
    }

    /// Process a YAML sequence to extract signatures.
    ///
    /// # Arguments
    /// * `seq` - A reference to a vector of YamlValue.
    /// * `out` - A mutable reference to a vector to collect signatures.
    ///
    /// # Returns
    /// * `None` - If the sequence is empty or contains no valid mappings.
    ///
    fn process_sequence(seq: &Vec<YamlValue>, out: &mut Vec<Signature>) {
        for item in seq {
            if let Some(m) = item.as_mapping() {
                if let Some(sig) = extract_signature_from_mapping(m) {
                    out.push(sig);
                }
            }
        }
    }

    /// Recursively process a YAML value to extract signatures.
    ///
    /// # Arguments
    /// * `val` - A reference to a YamlValue.
    /// * `out` - A mutable reference to a vector to collect signatures.
    ///
    /// # Returns
    /// * `None` - If the value is neither a mapping nor a sequence.
    ///
    fn process_value(val: &YamlValue, out: &mut Vec<Signature>) {
        match val {
            YamlValue::Mapping(map) => process_mapping(map, out),
            YamlValue::Sequence(seq) => process_sequence(seq, out),
            _ => {}
        }
    }

    /// Parse signatures from a YAML string.
    ///
    /// # Arguments
    /// * `content` - A string slice containing the YAML content.
    ///
    /// # Returns
    /// * `Ok(Vec<Signature>)` - If parsing is successful.
    /// * `Err(serde_yaml::Error)` - If parsing fails.
    ///
    fn parse_signatures_from_str(content: &str) -> Result<Vec<Signature>, serde_yaml::Error> {
        let val: YamlValue = serde_yaml::from_str(content)?;
        let mut out = Vec::new();
        process_value(&val, &mut out);
        Ok(out)
    }

    /// Load signatures from a YAML file and append them to the output vector.
    ///
    /// # Arguments
    /// * `path` - A reference to a Path of the YAML file.
    /// * `out` - A mutable reference to a vector to collect signatures.
    ///
    /// # Returns
    /// * `None` - If there was an error reading or parsing the file.
    ///
    fn load_signatures_from_file(path: &Path, out: &mut Vec<Signature>) {
        match std::fs::read_to_string(path) {
            Ok(content) => match parse_signatures_from_str(&content) {
                Ok(mut sigs) => out.append(&mut sigs),
                Err(e) => eprintln!(
                    "{}: {:?}: {}",
                    crate::localisator::get("error_parse_yaml"),
                    path,
                    e
                ),
            },
            Err(e) => eprintln!(
                "{}: {:?}: {}",
                crate::localisator::get("error_read_file"),
                path,
                e
            ),
        }
    }

    /// Recursively collect signatures from a directory and its subdirectories.
    ///
    /// # Arguments
    /// * `dir` - A reference to a Path of the directory.
    /// * `out` - A mutable reference to a vector to collect signatures.
    ///
    /// # Returns
    /// * `None` - If there was an error reading the directory.
    ///
    fn collect_signatures_from_dir(dir: &Path, out: &mut Vec<Signature>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_signatures_from_dir(&path, out);
                } else if is_yaml_file(&path) {
                    load_signatures_from_file(&path, out);
                }
            }
        }
    }

    let mut results = Vec::new();
    let base = Path::new("signatures");
    if !base.exists() {
        return Err(ScanError::Config(crate::localisator::get(
            "error_signatures_dir_not_found",
        )));
    }

    collect_signatures_from_dir(base, &mut results);
    results.sort_by(|a, b| a.name.cmp(&b.name).then(a.match_.cmp(&b.match_)));
    results.dedup_by(|a, b| a.name == b.name && a.match_ == b.match_);
    Ok(results)
}
