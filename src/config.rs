use crate::error::ScanError;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;

/// Read and parse the configuration file.
///
/// # Arguments
/// * `path` - A string slice that holds the path to the configuration file.
///
/// # Returns
/// * `Ok(HashMap<String, YamlValue>)` - If the configuration is successfully read and parsed.
/// * `Err(ScanError)` - If there is an error reading or parsing the configuration file.
///
pub fn read_config(path: &str) -> Result<HashMap<String, YamlValue>, ScanError> {
    let content = std::fs::read_to_string(path)?;
    serde_yaml::from_str::<HashMap<String, YamlValue>>(&content)
        .map_err(|e| ScanError::Config(e.to_string()))
}

/// Extract and validate configuration parameters.
///
/// # Arguments
/// * `config` - A reference to a HashMap containing configuration parameters.
///
/// # Returns
/// * `Ok((Arc<IpAddr>, u16, u16, usize, String))` - If all parameters are valid.
/// * `Err(ScanError)` - If any parameter is missing or invalid.
///
pub fn get_config(
    config: &HashMap<String, YamlValue>,
) -> Result<(std::sync::Arc<std::net::IpAddr>, u16, u16, usize, String), ScanError> {
    // Load language early for error messages
    let language = match config.get("language").and_then(|v| v.as_str()) {
        Some(lang) => lang.to_string(),
        None => "en".to_string(),
    };
    crate::localisator::init(&language);
    let ip: std::net::IpAddr = match config.get("ip").and_then(|v| v.as_str()) {
        Some(ip) => ip
            .parse()
            .map_err(|_| ScanError::Config(crate::localisator::get("error_invalid_ip")))?,
        None => {
            return Err(ScanError::Config(crate::localisator::get(
                "error_ip_not_found",
            )))
        }
    };
    let start_port = config
        .get("start_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u16;
    let end_port = config
        .get("end_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(65535) as u16;
    let max_threads = config
        .get("max_threads")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;
    Ok((
        std::sync::Arc::new(ip),
        start_port,
        end_port,
        max_threads,
        language,
    ))
}
