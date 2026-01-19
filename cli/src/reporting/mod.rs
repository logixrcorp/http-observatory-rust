use crate::models::ScanResult;
use std::fs::File;
use std::io::Write;

pub fn generate_report(result: &ScanResult, filename: &str, domain: &str) {
    let mut file = File::create(filename).expect("Unable to create report file");
    
    writeln!(file, "# Scan Report for {}\n", domain).unwrap();
    writeln!(file, "**Grade:** {} | **Score:** {}/100\n", result.grade, result.score).unwrap();
    
    writeln!(file, "## Security Headers").unwrap();
    writeln!(file, "| Header Check | Status | Score Modifier |").unwrap();
    writeln!(file, "|---|---|---|").unwrap();
    for res in &result.test_results {
        writeln!(file, "| {} | {} | {} |", res.description(), "Done", res.modifier()).unwrap();
    }
    
    writeln!(file, "\n## TLS Analysis").unwrap();
    writeln!(file, "* **Protocol:** {}", result.tls_result.protocol).unwrap();
    writeln!(file, "* **Cipher:** {}", result.tls_result.cipher).unwrap();
    for issue in &result.tls_result.issues {
         writeln!(file, "* ⚠️ **Issue:** {}", issue).unwrap();
    }

    if let Some(active) = &result.active_result {
        writeln!(file, "\n## Active Scan Results").unwrap();
        if active.xss_detected { writeln!(file, "* 🚨 **XSS Detected!**").unwrap(); }
        if active.sqli_detected { writeln!(file, "* 🚨 **SQLi Detected!**").unwrap(); }
        for issue in &active.issues {
            writeln!(file, "* {}", issue).unwrap();
        }
    } else {
        writeln!(file, "\n*Active scan disabled.*").unwrap();
    }
}
