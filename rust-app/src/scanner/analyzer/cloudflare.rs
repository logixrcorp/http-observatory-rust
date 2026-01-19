use crate::scanner::grade::TestResult;
use reqwest::header::HeaderMap;

pub fn analyze_cloudflare(headers: &HeaderMap) -> Vec<TestResult> {
    let mut results = Vec::new();

    // 1. Proxy Detection
    // Check if the Server header contains (case-insensitive) cloudflare.
    // Check for the presence of the CF-Ray header (Cloudflare's request tracing ID).
    // Check for CF-Visitor or CF-Connecting-IP
    let mut is_cloudflare = false;

    if let Some(server) = headers.get("server") {
        if let Ok(server_str) = server.to_str() {
            if server_str.to_lowercase().contains("cloudflare") {
                is_cloudflare = true;
            }
        }
    }

    if headers.contains_key("cf-ray") {
        is_cloudflare = true;
    }
    
    // Less common on response, but valid indicators if leaked
    if headers.contains_key("cf-visitor") || headers.contains_key("cf-connecting-ip") {
        is_cloudflare = true;
    }

    if is_cloudflare {
        results.push(TestResult::CloudflareProxyDetected);

        // 2. Cache Status
        // Parse the CF-Cache-Status header.
        if let Some(cache_status) = headers.get("cf-cache-status") {
             if let Ok(status) = cache_status.to_str() {
                 match status.to_uppercase().as_str() {
                     "HIT" | "REVALIDATED" | "UPDATED" => {
                         results.push(TestResult::CloudflareCacheHit);
                     },
                     "MISS" | "EXPIRED" | "DYNAMIC" | "BYPASS" => {
                         results.push(TestResult::CloudflareCacheMiss);
                     },
                     _ => {
                         // Unknown status, assume miss or just don't flag hit
                         results.push(TestResult::CloudflareCacheMiss);
                     }
                 }
             }
        } else {
             // Cloudflare detected but no cache status header?
             // Maybe explicitly disabled or not applicable. 
             results.push(TestResult::CloudflareCacheMiss);
        }

    } else {
        results.push(TestResult::CloudflareNotDetected);
    }

    results
}
