use crate::models::TlsResult;
use native_tls::{TlsConnector, Protocol};
use std::net::TcpStream;

pub fn analyze_tls(domain: &str) -> TlsResult {
    let mut issues = Vec::new();
    let mut is_secure = true;
    let mut protocol = "Unknown".to_string();
    let mut cipher = "Unknown".to_string(); // native-tls might not expose cipher safely on all platforms

    let connector = TlsConnector::new().unwrap();
    let target = format!("{}:443", domain);
    
    match TcpStream::connect(&target) {
        Ok(stream) => {
            match connector.connect(domain, stream) {
                Ok(_s) => {
                    // We established a connection. 
                    // native-tls doesn't easily expose the negotiated protocol version string in a cross-platform way 
                    // without digging into the inner stream (Schannel/OpenSSL).
                    // This is a limitation. For this generic CLI, we'll assume if we connected with default settings 
                    // (which usually default to valid TLS 1.2+ on modern OS), it's okay-ish.
                    // But we can try to force old versions to see if they work? 
                    // TlsConnector builder allows setting min/max versions.
                    
                    protocol = "Check Limited (NativeTLS)".to_string(); 
                    cipher = "Check Limited".to_string();
                    
                    // Check for obsolete protocols
                    if check_weak_protocol(domain, Protocol::Tlsv10) {
                        issues.push("Supports TLS 1.0 (Obsolete)".to_string());
                        is_secure = false;
                    }
                    if check_weak_protocol(domain, Protocol::Tlsv11) {
                         issues.push("Supports TLS 1.1 (Obsolete)".to_string());
                         is_secure = false;
                    }

                    // Reset to "Secure" or similar for display if no issues found
                    if is_secure {
                        protocol = "TLS 1.2+ (Likely)".to_string(); // simplistic
                    }
                },
                Err(e) => {
                    issues.push(format!("TLS Handshake failed: {}", e));
                    is_secure = false;
                }
            }
        },
        Err(e) => {
            issues.push(format!("Could not connect to {}: {}", target, e));
            is_secure = false;
        }
    }

    TlsResult {
        protocol,
        cipher,
        is_secure,
        issues,
    }
}

fn check_weak_protocol(domain: &str, proto: Protocol) -> bool {
    let builder = TlsConnector::builder().min_protocol_version(Some(proto)).max_protocol_version(Some(proto)).build();
    if let Ok(connector) = builder {
        if let Ok(stream) = TcpStream::connect(format!("{}:443", domain)) {
             if connector.connect(domain, stream).is_ok() {
                 return true;
             }
        }
    }
    false
}
