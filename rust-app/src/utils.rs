use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

pub fn is_valid_hostname(hostname: &str) -> bool {
    // 1. Check length
    if hostname.len() > 255 || hostname.is_empty() {
        return false;
    }

    // 2. Check for localhost or missing dots (standard FQDN expectation)
    if hostname == "localhost" || !hostname.contains('.') {
        return false;
    }

    // 3. Check for IP address (IPv4 or IPv6)
    if IpAddr::from_str(hostname).is_ok() {
        return false;
    }
    
    // 4. Basic charset check (let Url parser handle strict compliance or just simple regex)
    // For now, if it parses as a host in a URL, it's decent.
    let url_string = format!("http://{}", hostname);
    if let Ok(url) = Url::parse(&url_string) {
        if let Some(host_str) = url.host_str() {
             return host_str == hostname;
        }
    }

    false
}
