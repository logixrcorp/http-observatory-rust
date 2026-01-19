use crate::grader::TestResult;
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct ScanResult {
    pub domain: String,
    pub score: i16,
    pub grade: String,
    pub test_results: Vec<TestResult>,
    pub tls_result: TlsResult,
    pub active_result: Option<ActiveScanResult>,
}

#[derive(Debug, Serialize, Clone)]
pub struct TlsResult {
    pub protocol: String,
    pub cipher: String,
    pub is_secure: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ActiveScanResult {
    pub xss_detected: bool,
    pub sqli_detected: bool,
    pub outdated_cms: Option<String>,
    pub issues: Vec<String>,
}
