use crate::signatures::{identify_service, Signature};
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use threadpool::ThreadPool;
use indicatif::ProgressBar;
use crate::error::ScanError;

/// Format a duration into a human-readable string.
/// 
/// # Arguments
/// * `duration` - The duration to format.
/// 
/// Returns
/// * A formatted string representing the duration in the largest appropriate units.
///
pub fn format_duration(duration: Duration) -> String {
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
/// * `ip` - An Arc containing the target IP address.
/// * `port` - The port number to scan.
/// * `signatures` - An Arc containing a vector of service signatures.
///
/// # Returns
/// * `Some((u16, Option<String>))` - A tuple containing the open port and an optional identified service name.
/// * `None` - If the port is closed or unreachable.
///
pub fn scan_port(
    ip: Arc<IpAddr>,
    port: u16,
    signatures: Arc<Vec<Signature>>,
) -> Option<(u16, Option<String>)> {
    let addr = std::net::SocketAddr::new(*ip, port);
    if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
        let url = format!("http://{}:{}", ip, port);
        let client = Client::builder()
            .timeout(Duration::from_secs(1))
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

/// Scan multiple ports in parallel using a thread pool.\
/// 
/// # Arguments
/// * `ip` - An Arc containing the target IP address.
/// * `ports` - A vector of port numbers to scan.
/// * `signatures` - An Arc containing a vector of service signatures.
/// * `max_threads` - The maximum number of threads to use for scanning.
/// * `pb` - A reference to a ProgressBar to update progress.
///
/// # Returns
/// * `Ok(Vec<(u16, Option<String>)>)` - A vector of tuples containing open ports and their identified services.
/// * `Err(ScanError)` - If there was an error during scanning.
///
pub fn scan_ports_parallel(
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