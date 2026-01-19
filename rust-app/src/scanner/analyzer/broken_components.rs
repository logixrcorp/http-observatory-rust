use crate::scanner::grade::TestResult;
use regex::Regex;
use std::collections::HashSet;

pub fn analyze_broken_components(content: &str) -> Vec<TestResult> {
    let mut results = HashSet::new(); // Use Set for unique results

    // 1. Localhost Leaks
    // Regex: (?:href|src)=["']http://(?:localhost|127\.0\.0\.1)
    let localhost_regex = Regex::new(r#"(?:href|src)=["']http://(?:localhost|127\.0\.0\.1)"#).unwrap();
    if localhost_regex.is_match(content) {
        results.insert(TestResult::BrokenComponentLocalhostLink);
    }

    // 2. Placeholder/Empty Links
    // href="#" or href="" or href="javascript:void(0)"
    // Using simple regex on the string content
    let empty_link_regex = Regex::new(r#"href=["'](?:#|javascript:void\(0\))["']|href=["']["']"#).unwrap();
    if empty_link_regex.is_match(content) {
        results.insert(TestResult::BrokenComponentEmptyLink);
    }
    
    // 3. Template Syntax Leaks
    // {{ user }}, ${value}, [Insert Image Here]
    let handlebars_regex = Regex::new(r"\{\{\s*[a-zA-Z0-9_.]+\s*\}\}").unwrap();
    let js_template_regex = Regex::new(r"\$\{[a-zA-Z0-9_.]+\}").unwrap();
    let llm_placeholder_regex = Regex::new(r"\[Insert .* Here\]").unwrap();

    if handlebars_regex.is_match(content) || js_template_regex.is_match(content) || llm_placeholder_regex.is_match(content) {
        results.insert(TestResult::BrokenComponentTemplateLeak);
    }

    // 4. Lorem Ipsum
    // Case-insensitive "lorem ipsum"
    let lorem_regex = Regex::new(r"(?i)lorem ipsum").unwrap();
    if lorem_regex.is_match(content) {
        results.insert(TestResult::BrokenComponentLoremIpsum);
    }

    results.into_iter().collect()
}
