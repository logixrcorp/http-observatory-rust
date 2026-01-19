use crate::models::ActiveScanResult;
use reqwest::Client;
use std::time::Duration;

pub async fn active_scan(domain: &str) -> ActiveScanResult {
    let mut issues = Vec::new();
    let mut xss_detected = false;
    let mut sqli_detected = false;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Mozilla/5.0 (compatible; HTTP Observatory ActiveScanner/1.0)")
        .build()
        .unwrap_or_else(|_| Client::new());

    // 1. XSS Canary Check
    // We inject a harmless unique string and see if it reflects verbatim without encoding.
    let canary = "Reflect<Control>";
    let target = format!("http://{}/?q={}", domain, canary);
    
    match client.get(&target).send().await {
        Ok(res) => {
            if let Ok(text) = res.text().await {
                if text.contains(canary) {
                     // Simple reflection detected. Real XSS requires checking if tags are escaped, 
                     // but for a heuristic tool, reflection of raw arbitrary input is a strong signal.
                     // To be more precise, let's look for tag reflection.
                     let tag_canary = "<xss_test>";
                     if let Ok(res_tag) = client.get(format!("http://{}/?q={}", domain, tag_canary)).send().await {
                         if let Ok(text_tag) = res_tag.text().await {
                             if text_tag.contains(tag_canary) {
                                 xss_detected = true;
                                 issues.push(format!("Reflected Cross-Site Scripting (XSS) detected on parameter 'q' at {}", target));
                             }
                         }
                     }
                }
            }
        },
        Err(e) => {
            issues.push(format!("Active scan probe failed: {}", e));
        }
    }

    // 2. SQLi Canary (Error-based)
    // Inject single quote and look for common DB error messages.
    let sqli_target = format!("http://{}/?id=1'", domain);
    match client.get(&sqli_target).send().await {
        Ok(res) => {
             if let Ok(text) = res.text().await {
                 let lower = text.to_lowercase();
                 if lower.contains("syntax error") || lower.contains("sqlstate") || lower.contains("mysql_fetch") {
                     sqli_detected = true;
                     issues.push("Potential SQL Injection (SQLi) error message detected.".to_string());
                 }
             }
        },
        Err(_) => {}
    }

    if issues.is_empty() {
        issues.push("No obvious vulnerabilities found (Basic Canary)".to_string());
    }

    ActiveScanResult {
        xss_detected,
        sqli_detected,
        outdated_cms: None, // Requires more complex fingerprinting
        issues,
    }
}
