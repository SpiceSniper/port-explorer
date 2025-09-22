use port_explorer::scanner::{format_duration, scan_port, scan_ports_parallel};
use port_explorer::signatures::Signature;
use std::sync::Arc;
use std::time::Duration;
use std::net::IpAddr;
use indicatif::ProgressBar;

#[test]
fn test_format_duration() {
    // Test nanoseconds
    let duration = Duration::from_nanos(500);
    assert_eq!(format_duration(duration), "500ns");

    // Test milliseconds
    let duration = Duration::from_millis(250);
    assert_eq!(format_duration(duration), "250ms");

    // Test seconds
    let duration = Duration::from_secs(5) + Duration::from_millis(250);
    assert_eq!(format_duration(duration), "5s 250ms");

    // Test minutes
    let duration = Duration::from_secs(125); // 2 minutes 5 seconds
    assert_eq!(format_duration(duration), "2m 5s");

    // Test hours
    let duration = Duration::from_secs(3665); // 1 hour 1 minute 5 seconds
    assert_eq!(format_duration(duration), "1h 1m 5s");

    // Test zero duration
    let duration = Duration::from_nanos(0);
    assert_eq!(format_duration(duration), "0ns");
}

#[test]
fn test_scan_port_closed_port() {
    // Test scanning a port that should be closed (high port number)
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let port = 65534; // Usually closed
    
    let result = scan_port(ip, port, signatures);
    assert!(result.is_none(), "Port {} should be closed", port);
}

#[test]
fn test_scan_port_with_signatures() {
    // Test with some mock signatures
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![
        Signature {
            name: "Test Service".to_string(),
            match_: "test".to_string(),
        }
    ]);
    let port = 65533; // Usually closed
    
    let result = scan_port(ip, port, signatures);
    assert!(result.is_none(), "Port {} should be closed", port);
}

#[test]
fn test_scan_ports_parallel_empty_ports() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![];
    let max_threads = 10;
    let pb = ProgressBar::new(0);
    
    let result = scan_ports_parallel(ip, ports, signatures, max_threads, &pb);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_scan_ports_parallel_closed_ports() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![65530, 65531, 65532]; // Usually closed ports
    let max_threads = 2;
    let pb = ProgressBar::new(ports.len() as u64);
    
    let result = scan_ports_parallel(ip, ports, signatures, max_threads, &pb);
    assert!(result.is_ok());
    // Since these ports are likely closed, we expect an empty result
    let open_ports = result.unwrap();
    assert!(open_ports.is_empty(), "Expected no open ports, but found: {:?}", open_ports);
}

#[test]
fn test_scan_ports_parallel_with_signatures() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![
        Signature {
            name: "HTTP Server".to_string(),
            match_: "HTTP".to_string(),
        },
        Signature {
            name: "SSH".to_string(),
            match_: "SSH".to_string(),
        }
    ]);
    let ports = vec![65529]; // Usually closed port
    let max_threads = 1;
    let pb = ProgressBar::new(ports.len() as u64);
    
    let result = scan_ports_parallel(ip, ports, signatures, max_threads, &pb);
    assert!(result.is_ok());
    // Since this port is likely closed, we expect an empty result
    let open_ports = result.unwrap();
    assert!(open_ports.is_empty(), "Expected no open ports, but found: {:?}", open_ports);
}

#[test]
fn test_scan_ports_parallel_single_thread() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![65528]; // Usually closed port
    let max_threads = 1;
    let pb = ProgressBar::new(ports.len() as u64);
    
    let result = scan_ports_parallel(ip, ports, signatures, max_threads, &pb);
    assert!(result.is_ok());
    let open_ports = result.unwrap();
    assert!(open_ports.is_empty(), "Expected no open ports, but found: {:?}", open_ports);
}

#[test]
fn test_scan_ports_parallel_many_threads() {
    let ip = Arc::new("127.0.0.1".parse::<IpAddr>().unwrap());
    let signatures = Arc::new(vec![]);
    let ports = vec![65527, 65526]; // Usually closed ports
    let max_threads = 100;
    let pb = ProgressBar::new(ports.len() as u64);
    
    let result = scan_ports_parallel(ip, ports, signatures, max_threads, &pb);
    assert!(result.is_ok());
    let open_ports = result.unwrap();
    assert!(open_ports.is_empty(), "Expected no open ports, but found: {:?}", open_ports);
}