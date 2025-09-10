use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::thread;

use serde_yaml::Value;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
struct Signature {
    name: String,
    match_: String,
}

#[derive(Debug, Deserialize)]
struct SignatureFile {
    signatures: Vec<Signature>,
}

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
fn identify_service(response: &str, signatures: &[Signature]) -> Option<String> {
    for sig in signatures {
        if response.contains(&sig.match_) {
            return Some(sig.name.clone());
        }
    }
    None
}

fn scan_port(ip: Arc<IpAddr>, port: u16, signatures: Arc<Vec<Signature>>) -> Option<(u16, Option<String>)> {
    let addr = std::net::SocketAddr::new(*ip, port);
    if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok() {
        // Try HTTP detection
        let url = format!("http://{}:{}", ip, port);
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build();
        if let Ok(client) = client {
            if let Ok(resp) = client.get(&url)
                .header(USER_AGENT, "port-explorer")
                .send() {
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

fn read_config(path: &str) -> HashMap<String, Value> {
    match fs::read_to_string(path) {
        Ok(content) => {
            serde_yaml::from_str::<HashMap<String, Value>>(&content).unwrap_or_else(|_| {
                eprintln!("Failed to parse config file: {}", path);
                std::process::exit(1);
            })
        },
        Err(_) => {
            eprintln!("Config file not found: {}", path);
            std::process::exit(1);
        }
    }
}

fn load_signatures() -> Vec<Signature> {
    let mut all_signatures = Vec::new();
    if let Ok(entries) = fs::read_dir("signatures") {
        for entry in entries.flatten() {
            if let Some(extension) = entry.path().extension() {
                if extension == "yaml" || extension == "yml" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if let Ok(sig_file) = serde_yaml::from_str::<SignatureFile>(&content) {
                            all_signatures.extend(sig_file.signatures);
                        }
                    }
                }
            }
        }
    }

    all_signatures
}

fn get_config(config: &HashMap<String, Value>) -> (Arc<IpAddr>, Arc<Vec<Signature>>, u16, u16, usize) {
    let ip: IpAddr = match config.get("ip").and_then(|v| v.as_str()) {
        Some(ip) => ip.parse().unwrap_or_else(|_| {
            eprintln!("Invalid IP address in config.");
            std::process::exit(1);
        }),
        None => {
            eprintln!("IP address not found in config.");
            std::process::exit(1);
        }
    };
    let ip = Arc::new(ip);
    
    let signatures = Arc::new(load_signatures());
    
    let start_port = match config.get("start_port").and_then(|v| v.as_u64()) {
        Some(port) => {
            if port > 65535 {
                eprintln!("Start port {} is out of range (1-65535)", port);
                std::process::exit(1);
            }
            port as u16
        },
        None => 1
    };
    
    let end_port = match config.get("end_port").and_then(|v| v.as_u64()) {
        Some(port) => {
            if port > 65535 {
                eprintln!("End port {} is out of range (1-65535)", port);
                std::process::exit(1);
            }
            port as u16
        },
        None => 65535
    };
    
    if start_port > end_port {
        eprintln!("Start port {} cannot be greater than end port {}", start_port, end_port);
        std::process::exit(1);
    }
    
    let max_threads = match config.get("max_threads").and_then(|v| v.as_u64()) {
        Some(threads) => {
            if threads == 0 {
                eprintln!("Max threads cannot be zero");
                std::process::exit(1);
            }
            if threads > 1000 {
                eprintln!("Max threads {} is too high (maximum: 1000)", threads);
                std::process::exit(1);
            }
            threads as usize
        },
        None => 100
    };
    (ip, signatures, start_port, end_port, max_threads)
    }


fn main() {

    let scan_start = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.yaml"
    };

    let config = read_config(config_path);
    let (ip, signatures, start_port, end_port, max_threads) = get_config(&config);

    let mut handles = Vec::new();
    let ports: Vec<u16> = (start_port..=end_port).collect();
    let chunk_size = (ports.len() / max_threads) + 1;

    for chunk in ports.chunks(chunk_size) {
        let ip = Arc::clone(&ip);
        let chunk = chunk.to_vec();
        let signatures = Arc::clone(&signatures);
        let handle = thread::spawn(move || {
            chunk.into_iter()
                .filter_map(|port| scan_port(ip.clone(), port, Arc::clone(&signatures)))
                .collect::<Vec<(u16, Option<String>)>>()
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(ports) => open_ports.extend(ports),
            Err(_) => eprintln!("Thread panicked"),
        }
    }

    let ip_str = config.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    use std::io::Write;
    use chrono::Local;
    use std::time::Instant;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_path = format!("logs/scan_{}.log", timestamp);
    let mut log = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create log file: {}", e);
            return;
        }
    };

        let scan_duration = scan_start.elapsed();
        let scan_duration_str = format_duration(scan_duration);

        let header = format!(
            "Scan started: {}\nPort range: {}-{}\nDuration: {}\nTarget: {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            start_port,
            end_port,
            scan_duration_str,
            ip_str
        );
        let _ = log.write_all(header.as_bytes());

        let open_ports_count = open_ports.len();
        if open_ports_count == 0 {
            let msg = format!("No open ports found on {}\n", ip_str);
            print!("{}", msg);
            let _ = log.write_all(msg.as_bytes());
            print!("Scanned ports: {}-{}\nDuration: {}\nOpen ports: 0\n", start_port, end_port, scan_duration_str);
        } else {
        let ports_header = format!("Open ports on {}:\n", ip_str);
        print!("{}", ports_header);
        let _ = log.write_all(ports_header.as_bytes());
        for (port, service) in &open_ports {
            let line = match service {
                Some(name) => format!("{}: {}\n", port, name),
                None => format!("{}: open\n", port),
            };
            print!("{}", line);
            let _ = log.write_all(line.as_bytes());
        }
        print!("Scanned ports: {}-{}\nDuration: {}\nOpen ports: {}\n", start_port, end_port, scan_duration_str, open_ports_count);
    }
}
