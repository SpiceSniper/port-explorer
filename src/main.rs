mod error;
mod localisator;
mod config;
mod signatures;

use std::sync::Arc;
use std::net::{IpAddr, TcpStream};
use indicatif::{ProgressBar, ProgressStyle};
use threadpool::ThreadPool;
use chrono::Local;
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use std::io::Write;
use error::ScanError;
use signatures::{Signature, identify_service, load_signatures};

/// Format a duration into a human-readable string.
///
/// # Arguments
/// * `duration` - The duration to format.
/// 
/// Returns
/// * A formatted string representing the duration in the largest appropriate units.
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

/// Scan a single port on the given IP address.
///
/// # Arguments
/// * `ip` - An Arc-wrapped IpAddr to scan.
/// * `port` - The port number to scan.
/// * `signatures` - An Arc-wrapped vector of Signature for service identification.
///
/// # Returns
/// * `Some((u16, Option<String>))` - If the port is open and a service is identified.
/// * `None` - If the port is closed or no service is identified.
/// 
fn scan_port(
    ip: Arc<IpAddr>,
    port: u16,
    signatures: Arc<Vec<Signature>>,
) -> Option<(u16, Option<String>)> {
    let addr = std::net::SocketAddr::new(*ip, port);
    if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
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

/// Scan multiple ports in parallel using a thread pool.
/// 
/// # Arguments
/// * `ip` - An Arc-wrapped IpAddr to scan.
/// * `ports` - A vector of port numbers to scan.
/// * `signatures` - An Arc-wrapped vector of Signature for service identification.
/// * `max_threads` - The maximum number of threads to use.
/// * `pb` - A reference to a ProgressBar for progress tracking.
///
/// # Returns
/// * `Ok(Vec<(u16, Option<String>)>)` - A vector of open ports and their identified services.
/// * `Err(ScanError)` - If an error occurs during scanning.
/// 
fn scan_ports_parallel(
    ip: Arc<IpAddr>,
    ports: Vec<u16>,
    signatures: Arc<Vec<Signature>>,
    max_threads: usize,
    pb: &ProgressBar,
) -> Result<Vec<(u16, Option<String>)>, ScanError> {
    let pool = ThreadPool::new(max_threads);
    let open_ports = Arc::new(std::sync::Mutex::new(Vec::new()));
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
    let mut result = Arc::try_unwrap(open_ports).unwrap().into_inner().unwrap();
    result.sort_by_key(|k| k.0);
    Ok(result)
}

/// The main entry point of the application.
///
fn main() {
    let scan_start = std::time::Instant::now();
    let config_path = "config.yaml";
    let config = match config::read_config(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    let (ip, start_port, end_port, max_threads, _language) = match config::get_config(&config) {
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
    let open_ports = match scan_ports_parallel(ip.clone(), ports, signatures.clone(), max_threads, &pb) {
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
