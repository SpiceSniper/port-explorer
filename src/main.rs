use clap::Parser;
mod config;
mod error;
mod localisator;
mod signatures;
mod scanner;

use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use signatures::load_signatures;
use std::io::Write;
use std::sync::Arc;
use scanner::{format_duration, scan_ports_parallel};

/// Command-line arguments for Port Explorer
/// 
/// Fields:
/// * `ip` - Target IP address (e.g., "192.168.1
/// * `start_port` - Starting port number (e.g., 1)
/// * `end_port` - Ending port number (e.g., 65535)
/// * `max_threads` - Maximum number of threads to use (e.g., 100)
/// * `language` - Language code for localization (e.g., "en", "es")
/// 
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target IP address
    #[arg(long)]
    ip: Option<String>,

    /// Start port
    #[arg(long)]
    start_port: Option<u16>,

    /// End port
    #[arg(long)]
    end_port: Option<u16>,

    /// Max threads
    #[arg(long)]
    max_threads: Option<usize>,

    /// Language
    #[arg(long)]
    language: Option<String>,
}

/// Format a duration into a human-readable string.
///
/// # Arguments
/// * `duration` - The duration to format.
///
/// Returns
/// * A formatted string representing the duration in the largest appropriate units.
/// The main entry point of the application.
///
fn main() {
    let args = Args::parse();
    let scan_start = std::time::Instant::now();
    let config_path = "config.yaml";
    let mut config = match config::read_config(config_path) {
        Ok(cfg) => cfg,
        Err(_) => std::collections::HashMap::new(),
    };
    // Override config with CLI args if provided
    if let Some(ip) = &args.ip {
        config.insert("ip".to_string(), serde_yaml::Value::String(ip.clone()));
    }
    if let Some(start_port) = args.start_port {
        config.insert("start_port".to_string(), serde_yaml::Value::Number(start_port.into()));
    }
    if let Some(end_port) = args.end_port {
        config.insert("end_port".to_string(), serde_yaml::Value::Number(end_port.into()));
    }
    if let Some(max_threads) = args.max_threads {
        config.insert("max_threads".to_string(), serde_yaml::Value::Number((max_threads as u64).into()));
    }
    if let Some(language) = &args.language {
        config.insert("language".to_string(), serde_yaml::Value::String(language.clone()));
    }
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
    
    let log_path = "logs";
    if let Err(e) = std::fs::create_dir_all(log_path) {
        eprintln!("{}: {}", localisator::get("error_log_dir_create"), e);
        return;
    }
    
    let log_file_path = std::path::Path::new(log_path).join(format!("scan_{}.log", timestamp));
    let mut log = match std::fs::File::create(&log_file_path) {
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
