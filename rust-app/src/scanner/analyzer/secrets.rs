use crate::scanner::grade::TestResult;
use regex::Regex;
use std::collections::HashSet;

pub fn analyze_secrets(content: &str) -> Vec<TestResult> {
    let mut results = HashSet::new(); // Use Set to avoid duplicates if multiple matches found for same category

    // AI Keys
    let openai_pattern = Regex::new(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}|sk-proj-[a-zA-Z0-9_-]+").unwrap();
    let anthropic_pattern = Regex::new(r"sk-ant-api03-[a-zA-Z0-9_-]+").unwrap();
    let huggingface_pattern = Regex::new(r"hf_[a-zA-Z0-9]{30,}").unwrap();

    // Cloud Keys
    let aws_pattern = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    let google_pattern = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();
    let stripe_pattern = Regex::new(r"sk_live_[0-9a-zA-Z]{24}").unwrap();

    // Generic / Suspicious
    // (?:api_key|auth_token|access_token|secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]
    let generic_pattern = Regex::new(r#"(?:api_key|auth_token|access_token|secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]"#).unwrap();
    
    // HMAC / Private Keys
    let private_key_pattern = Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap();

    // Hardcoded Passwords
    // password\s*=\s*['"][^'"]{6,}['"] -- exclude "password" or empty
    // We need to look for actual assignments, avoid form fields or generic text. 
    // The pattern provided: password\s*=\s*['"][^'"]{6,}['"]
    let password_pattern = Regex::new(r#"password\s*=\s*['"][^'"]{6,}['"]"#).unwrap();


    // Content checks
    if openai_pattern.is_match(content) || anthropic_pattern.is_match(content) || huggingface_pattern.is_match(content) {
        results.insert(TestResult::SecretsDetectedAiKey);
    }

    if aws_pattern.is_match(content) || google_pattern.is_match(content) || stripe_pattern.is_match(content) {
        results.insert(TestResult::SecretsDetectedCloudKey);
    }

    if generic_pattern.is_match(content) || private_key_pattern.is_match(content) {
        // Exclude common placeholders if regex matched widely?
        // Pattern seems specific enough for now (requires assignment)
        if !content.contains("YOUR_API_KEY") && !content.contains("your_api_key") {
             results.insert(TestResult::SecretsDetectedGenericKey);
        }
    }

    if password_pattern.is_match(content) {
        // Basic false positive check
        if !content.contains("password = \"password\"") && !content.contains("password = ''") {
             results.insert(TestResult::SecretsDetectedHardcodedPassword);
        }
    }

    results.into_iter().collect()
}
