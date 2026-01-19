use crate::scanner::grade::TestResult;
use regex::Regex;


pub fn analyze_vibe_coding(html_content: &str, exposed_configs_found: bool, source_map_file_found: bool, source_map_ref_found: bool) -> Vec<TestResult> {
    let mut results = Vec::new();
    let mut issue_found = false;

    // 1. Check for Exposed Configs (Critical)
    if exposed_configs_found {
        results.push(TestResult::VibeCodingExposedConfig);
        issue_found = true;
    }

    // 2. Check for Source Maps
    if source_map_file_found {
        results.push(TestResult::VibeCodingSourceMapFileDetected);
        issue_found = true;
    }
    if source_map_ref_found {
        results.push(TestResult::VibeCodingSourceMapReferenceDetected);
        issue_found = true;
    }

    // 3. Content Scan for AI Artifacts
    // Common phrases found in lazy AI copy-pastes
    let ai_phrases = [
        "As an AI language model",
        "I cannot fulfill this request",
        "Here is the code",
        "Here is the snippet",
        "regenerate response",
        "// TODO: AI",
        "Note: This code",
        "I'm sorry, but",
    ];

    let found_ai_artifact = ai_phrases.iter().any(|phrase| html_content.contains(phrase));
    
    if found_ai_artifact {
        results.push(TestResult::VibeCodingAiArtifactsDetected);
        issue_found = true;
    }

    // 4. DB & Backend Leak Check
    let db_issues = analyze_direct_db_access(html_content);
    if !db_issues.is_empty() {
        issue_found = true;
        results.extend(db_issues);
    }

    if !issue_found {
        results.push(TestResult::VibeCodingClean);
    }

    results
}

fn analyze_direct_db_access(content: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Connection Strings
    // (postgres|mysql|mongodb(?:\+srv)?|mssql|redis)://[a-zA-Z0-9_\-:]+@
    let conn_str_regex = Regex::new(r"(postgres|mysql|mongodb(?:\+srv)?|mssql|redis)://[a-zA-Z0-9_\-:]+@").unwrap();
    if conn_str_regex.is_match(content) {
        results.push(TestResult::VibeCodingDirectDatabaseConnection);
    }

    // Server-Side Library Imports
    // require\(['"](pg|mysql2?|sqlite3|mongoose|sequelize|typeorm)['"]\)
    // from ['"](pg|mysql2?|sqlite3|mongoose|sequelize|typeorm)['"]
    let require_regex = Regex::new(r#"require\(['"](pg|mysql2?|sqlite3|mongoose|sequelize|typeorm)['"]\)"#).unwrap();
    let import_regex = Regex::new(r#"from ['"](pg|mysql2?|sqlite3|mongoose|sequelize|typeorm)['"]"#).unwrap();
    
    if require_regex.is_match(content) || import_regex.is_match(content) {
         results.push(TestResult::VibeCodingServerSideImportDetected);
    }

    // Raw SQL Queries
    // "SELECT \* FROM (Case insensitive)
    // "INSERT INTO \w+ VALUES
    // "DELETE FROM \w+
    // Using simple regex with case insensitivity
    let select_regex = Regex::new(r#"(?i)"SELECT \* FROM"#).unwrap();
    let insert_regex = Regex::new(r#"(?i)"INSERT INTO \w+ VALUES"#).unwrap();
    let delete_regex = Regex::new(r#"(?i)"DELETE FROM \w+"#).unwrap();

    if select_regex.is_match(content) || insert_regex.is_match(content) || delete_regex.is_match(content) {
        results.push(TestResult::VibeCodingSqlLogicDetected);
    }

    results
}
