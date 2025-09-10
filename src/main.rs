use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use serde::Deserialize;
use serde_yaml::Value as YamlValue;

use chrono::Local;

use indicatif::{ProgressBar, ProgressStyle};

use threadpool::ThreadPool;

mod localisator;

/// Signature structure for service identification
///
/// # Fields:
/// * 'name' - Name of the service (e.g., "Apache", "nginx")
/// * 'match_' - Substring to match in the service response for identification
///
#[derive(Debug, Deserialize, Clone)]
struct Signature {
    name: String,
    match_: String,
}

/// Format a `std::time::Duration` into a human-readable string.
///
/// # Arguments
/// * `duration` - The duration to format.
///
/// # Returns
/// A formatted string representing the duration in the largest appropriate units.
///
fn format_duration(duration: std::time::Duration) -> String {
    let total_ms = duration.as_millis();
    let total_ns = duration.as_nanos();
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    let millis = duration.subsec_millis();
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else if seconds > 0 {
        format!("{}s {}ms", seconds, millis)
    } else if millis > 0 {
        format!("{}ms", total_ms)
    } else {
        format!("{}ns", total_ns)
    }
}

/// Identify the service based on response content and known signatures.
///
/// # Arguments
/// * `response` - The response string to analyze.
/// * `signatures` - A list of known service signatures.
///
/// # Returns
/// An `Option<String>` containing the service name if identified, or `None` if not identified.
///
fn identify_service(response: &str, signatures: &[Signature]) -> Option<String> {
    for sig in signatures {
        if response.contains(&sig.match_) {
            return Some(sig.name.clone());
        }
    }
    None
}

/// Scan a single port on the given IP address.
///
/// # Arguments
/// * `ip` - The target IP address.
/// * `port` - The port number to scan.
/// * `signatures` - A list of known service signatures for identification.
///
/// # Returns
/// An `Option<(u16, Option<String>)>` containing the port number and the service name if identified, or `None` if not identified.
///
fn scan_port(
    ip: Arc<IpAddr>,
    port: u16,
    signatures: Arc<Vec<Signature>>,
) -> Option<(u16, Option<String>)> {
    let addr = std::net::SocketAddr::new(*ip, port);
    if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
        // Try HTTP detection
        let url = format!("http://{}:{}", ip, port);
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build();
        if let Ok(client) = client {
            if let Ok(resp) = client.get(&url).header(USER_AGENT, "port-explorer").send() {
                if let Ok(text) = resp.text() {
                    let service = identify_service(&text, &signatures);
                    return Some((port, service));
                }
            }
        }
        Some((port, None))
    } else {
        None
    }
}

/// Custom error type for port explorer
///
enum ScanError {
    Config(String),
    Io(std::io::Error),
}

/// Display implementation for ScanError
///
impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Config(msg) => write!(f, "Config error: {}", msg),
            ScanError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

/// Convert std::io::Error into ScanError
///
impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}

/// Read and parse the configuration file.
/// # Arguments
/// * `path` - The path to the configuration file.
///
/// # Returns
/// A `Result<HashMap<String, Value>, ScanError>` containing the parsed configuration.
///
fn read_config(path: &str) -> Result<HashMap<String, YamlValue>, ScanError> {
    let content = std::fs::read_to_string(path)?;
    serde_yaml::from_str::<HashMap<String, YamlValue>>(&content)
        .map_err(|e| ScanError::Config(e.to_string()))
}

/// Load all signatures from YAML files in the "signatures" directory.
///
/// # Returns
/// A `Result<Vec<Signature>, ScanError>` containing the loaded signatures.
///
fn load_signatures() -> Result<Vec<Signature>, ScanError> {
    /// Process a YAML value to extract signatures.
    ///
    /// # Arguments
    /// * `val` - The YAML value to process.
    /// * `out` - A mutable reference to the output vector of signatures.
    ///
    fn process_value(val: YamlValue, out: &mut Vec<Signature>) {
        match val {
            YamlValue::Mapping(map) => {
                // If there's a "signatures" key with a sequence
                if let Some(seq) = map
                    .get(&YamlValue::from("signatures"))
                    .and_then(|v| v.as_sequence())
                {
                    for item in seq {
                        if let Some(m) = item.as_mapping() {
                            let name = m.get(&YamlValue::from("name")).and_then(|v| v.as_str());
                            let match_str = m
                                .get(&YamlValue::from("match_"))
                                .and_then(|v| v.as_str())
                                .or_else(|| {
                                    m.get(&YamlValue::from("match")).and_then(|v| v.as_str())
                                });
                            if let (Some(n), Some(ms)) = (name, match_str) {
                                out.push(Signature {
                                    name: n.to_string(),
                                    match_: ms.to_string(),
                                });
                            }
                        }
                    }
                    return;
                }
                // Otherwise treat as name -> match mapping
                for (k, v) in map {
                    if let (Some(name), Some(ms)) = (k.as_str(), v.as_str()) {
                        out.push(Signature {
                            name: name.to_string(),
                            match_: ms.to_string(),
                        });
                    }
                }
            }
            YamlValue::Sequence(seq) => {
                for item in seq {
                    if let Some(m) = item.as_mapping() {
                        let name = m.get(&YamlValue::from("name")).and_then(|v| v.as_str());
                        let match_str = m
                            .get(&YamlValue::from("match_"))
                            .and_then(|v| v.as_str())
                            .or_else(|| m.get(&YamlValue::from("match")).and_then(|v| v.as_str()));
                        if let (Some(n), Some(ms)) = (name, match_str) {
                            out.push(Signature {
                                name: n.to_string(),
                                match_: ms.to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Recursively walk through the directory to find YAML files.
    ///
    /// # Arguments
    /// * `dir` - The directory path to walk.
    /// * `out` - A mutable reference to the output vector of signatures.
    ///
    fn walk(dir: &Path, out: &mut Vec<Signature>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
                        match std::fs::read_to_string(&path) {
                            Ok(content) => match serde_yaml::from_str::<YamlValue>(&content) {
                                Ok(val) => process_value(val, out),
                                Err(e) => eprintln!(
                                    "{}: {:?}: {}",
                                    localisator::get("error_parse_yaml"),
                                    path,
                                    e
                                ),
                            },
                            Err(e) => eprintln!(
                                "{}: {:?}: {}",
                                localisator::get("error_read_file"),
                                path,
                                e
                            ),
                        }
                    }
                }
            }
        }
    }

    let mut results = Vec::new();
    let base = Path::new("signatures");
    if !base.exists() {
        return Err(ScanError::Config(localisator::get(
            "error_signatures_dir_not_found",
        )));
    }

    walk(base, &mut results);

    results.sort_by(|a, b| a.name.cmp(&b.name).then(a.match_.cmp(&b.match_)));
    results.dedup_by(|a, b| a.name == b.name && a.match_ == b.match_);
    Ok(results)
}

/// Extract and validate configuration parameters.
///
/// # Arguments
/// * `config` - A reference to the configuration HashMap.
///
/// Returns a tuple containing:
/// * `Arc<IpAddr>` - The target IP address.
/// * `u16` - The start port.
/// * `u16` - The end port.
/// * `usize` - The maximum number of threads.
///
fn get_config(
    config: &HashMap<String, YamlValue>,
) -> Result<(Arc<IpAddr>, u16, u16, usize, String), ScanError> {
    // Load language early for error messages
    let language = match config.get("language").and_then(|v| v.as_str()) {
        Some(lang) => lang.to_string(),
        None => "en".to_string(),
    };
    // Init Localisator early, to provide error messages in the correct language
    localisator::init(&language);
    let ip: IpAddr = match config.get("ip").and_then(|v| v.as_str()) {
        Some(ip) => ip
            .parse()
            .map_err(|_| ScanError::Config(localisator::get("error_invalid_ip")))?,
        None => return Err(ScanError::Config(localisator::get("error_ip_not_found"))),
    };
    let ip = Arc::new(ip);

    let start_port = match config.get("start_port").and_then(|v| v.as_u64()) {
        Some(port) => {
            if port > 65535 {
                let msg =
                    localisator::get("error_start_port_range").replace("{port}", &port.to_string());
                return Err(ScanError::Config(msg));
            }
            port as u16
        }
        None => 1,
    };

    let end_port = match config.get("end_port").and_then(|v| v.as_u64()) {
        Some(port) => {
            if port > 65535 {
                let msg =
                    localisator::get("error_end_port_range").replace("{port}", &port.to_string());
                return Err(ScanError::Config(msg));
            }
            port as u16
        }
        None => 65535,
    };

    if start_port > end_port {
        let msg = localisator::get("error_start_gt_end")
            .replace("{start}", &start_port.to_string())
            .replace("{end}", &end_port.to_string());
        return Err(ScanError::Config(msg));
    }

    let max_threads = match config.get("max_threads").and_then(|v| v.as_u64()) {
        Some(threads) => {
            if threads <= 0 {
                let msg = localisator::get("error_max_threads_zero")
                    .replace("{threads}", &threads.to_string());
                return Err(ScanError::Config(msg));
            }
            if threads > 1000 {
                let msg = localisator::get("error_max_threads_high")
                    .replace("{threads}", &threads.to_string());
                return Err(ScanError::Config(msg));
            }
            threads as usize
        }
        None => 100,
    };
    Ok((ip, start_port, end_port, max_threads, language))
}

/// Scan ports in parallel using a thread pool, updating the progress bar and returning open ports.
///
/// # Arguments
/// * `ip` - The target IP address.
/// * `ports` - A vector of port numbers to scan.
/// * `signatures` - A list of known service signatures for identification.
/// * `max_threads` - The maximum number of threads to use.
/// * `pb` - A reference to the progress bar to update.
///
/// # Returns
/// A vector of tuples containing open port numbers and their identified services (if any).
///
fn scan_ports_parallel(
    ip: Arc<IpAddr>,
    ports: Vec<u16>,
    signatures: Arc<Vec<Signature>>,
    max_threads: usize,
    pb: &ProgressBar,
) -> Result<Vec<(u16, Option<String>)>, ScanError> {
    let pool = ThreadPool::new(max_threads);
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(pb.clone());

    for port in ports {
        let ip = Arc::clone(&ip);
        let signatures = Arc::clone(&signatures);
        let open_ports = Arc::clone(&open_ports);
        let progress = Arc::clone(&progress);
        pool.execute(move || {
            if let Some(res) = scan_port(ip, port, signatures) {
                open_ports.lock().unwrap().push(res);
            }
            progress.inc(1);
        });
    }
    pool.join();
    let result = Arc::try_unwrap(open_ports).unwrap().into_inner().unwrap();
    Ok(result)
}

/// Main function to execute the port scanning logic.
///
fn main() {
    let scan_start = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.yaml"
    };

    let config = match read_config(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    let (ip, start_port, end_port, max_threads, _language) = match get_config(&config) {
        Ok(vals) => vals,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    let signatures = match load_signatures() {
        Ok(sigs) => Arc::new(sigs),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let ports: Vec<u16> = (start_port..=end_port).collect();
    let pb = ProgressBar::new(ports.len() as u64);
    pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .expect(&localisator::get("error_progress_bar_template"))
                .progress_chars("=>-")
        );
    let open_ports =
        match scan_ports_parallel(ip.clone(), ports, signatures.clone(), max_threads, &pb) {
            Ok(ports) => ports,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        };
    pb.finish_with_message(localisator::get("scan_complete"));

    let ip_str = config.get("ip").and_then(|v| v.as_str()).unwrap_or("");

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_path = format!("logs/scan_{}.log", timestamp);
    let mut log = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}: {}", localisator::get("error_log_file_create"), e);
            return;
        }
    };

    let scan_duration = scan_start.elapsed();
    let scan_duration_str = format_duration(scan_duration);

    let header = format!(
        "{} {}\n{} {}-{}\n{} {}\n{} {}\n",
        localisator::get("scan_started"),
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        localisator::get("port_range"),
        start_port,
        end_port,
        localisator::get("duration"),
        scan_duration_str,
        localisator::get("target"),
        ip_str
    );
    let _ = log.write_all(header.as_bytes());

    let open_ports_count = open_ports.len();
    if open_ports_count == 0 {
        let msg = format!("{} {}\n", localisator::get("no_open_ports"), ip_str);
        print!("{}", msg);
        let _ = log.write_all(msg.as_bytes());
        print!(
            "{} {}-{}\n{} {}\n{} 0\n",
            localisator::get("scanned_ports"),
            start_port,
            end_port,
            localisator::get("duration"),
            scan_duration_str,
            localisator::get("open_ports_count"),
        );
    } else {
        let ports_header = format!("{} {}:\n", localisator::get("open_ports"), ip_str);
        print!("{}", ports_header);
        let _ = log.write_all(ports_header.as_bytes());
        for (port, service) in &open_ports {
            let line = match service {
                Some(name) => format!("{}: {}\n", port, name),
                None => format!("{}: {}\n", port, localisator::get("open")),
            };
            print!("{}", line);
            let _ = log.write_all(line.as_bytes());
        }
        print!(
            "{} {}-{}\n{} {}\n{} {}\n",
            localisator::get("scanned_ports"),
            start_port,
            end_port,
            localisator::get("duration"),
            scan_duration_str,
            localisator::get("open_ports_count"),
            open_ports_count
        );
    }
}
