use crate::scanner::grade::TestResult;
use regex::Regex;
use reqwest::Client;

pub async fn analyze_supabase(content: &str, client: &Client) -> Vec<TestResult> {
    let mut results = Vec::new();

    // 1. Static Analysis (Credentials)
    // SUPABASE_URL\s*[:=]\s*['"]https://([a-z0-9]+)\.supabase\.co['"]
    // SUPABASE_KEY\s*[:=]\s*['"](ey[a-zA-Z0-9._-]+)['"]
    
    // We capture project ref and key for active audit
    // Using slightly loose regex to catch:
    // const supabaseUrl = 'https://xyz.supabase.co'
    // process.env.NEXT_PUBLIC_SUPABASE_URL = "..."
    let url_regex = Regex::new(r"https://([a-z0-9]+)\.supabase\.co").unwrap();
    let key_regex = Regex::new(r"ey[a-zA-Z0-9._-]{20,}").unwrap(); // JWTs are usually long
    
    // Explicit assignment check for better accuracy on "Exposed" scoring
    let url_assignment_regex = Regex::new(r#"SUPABASE_URL\s*[:=]\s*['"]https://([a-z0-9]+)\.supabase\.co['"]"#).unwrap();
    let key_assignment_regex = Regex::new(r#"SUPABASE_(?:ANON_)?KEY\s*[:=]\s*['"](ey[a-zA-Z0-9._-]+)['"]"#).unwrap();
    // Also common JS patterns: const supabaseKey = '...'
    // But let's stick to the prompt's specific regexes first + generic JWT finding if it looks like a supabase key context

    let mut project_ref = String::new();
    let mut anon_key = String::new();

    if let Some(caps) = url_regex.captures(content) {
        // found a supabase url
        project_ref = caps[1].to_string();
    }
    if let Some(caps) = key_regex.captures(content) {
        // found something that looks like a JWT/Key
        anon_key = caps[0].to_string();
    }

    // Check specific assignment for "CredentialsExposed" flag
    if url_assignment_regex.is_match(content) && key_assignment_regex.is_match(content) {
        results.push(TestResult::SupabaseCredentialsExposed);
    } else if !project_ref.is_empty() && !anon_key.is_empty() {
        // If we found both URL and Key generally, we can arguably flag it, 
        // but let's be strict per prompt for the -50 score, OR just check if we found them at all.
        // The prompt says: "Found SUPABASE_URL and SUPABASE_KEY...".
        // Let's rely on the regexes finding *any* valid looking pair to proceed to audit, 
        // and if they match the explicit assignment patterns, we definitely flag Exposed.
        if project_ref.len() > 0 && anon_key.len() > 0 {
             results.push(TestResult::SupabaseCredentialsExposed);
        }
    }


    // 2. Static Analysis (Queries)
    // .from(['"]([a-zA-Z0-9_]+)['"]).select(
    let query_regex = Regex::new(r#"\.from\(['"]([a-zA-Z0-9_]+)['"]\)\.select\("#).unwrap();
    let mut table_name = String::new();

    if let Some(caps) = query_regex.captures(content) {
        results.push(TestResult::SupabaseDirectClientQueryDetected);
        table_name = caps[1].to_string();
    }


    // 3. Active Audit (Phase 2)
    // Only if we found URL, Key, and Table Name
    if !project_ref.is_empty() && !anon_key.is_empty() && !table_name.is_empty() {
        let audit_url = format!("https://{}.supabase.co/rest/v1/{}?select=*&limit=1", project_ref, table_name);
        
        let req = client.get(&audit_url)
            .header("apikey", &anon_key)
            .header("Authorization", format!("Bearer {}", anon_key));
            
        // Use timeout and error handling
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    // Check if body is JSON array
                    if let Ok(text) = resp.text().await {
                        if text.trim().starts_with('[') && text.trim().ends_with(']') && text.len() > 2 {
                             // It's an array and not empty (len > 2 means content usually)
                             // Prompt: "returns a JSON array: Mark as SupabaseRlsNotEnforced"
                             // Actually, even empty array [] means read was allowed. 401/403 means denied.
                             // "If 200 OK and returns a JSON array: Mark as SupabaseRlsNotEnforced"
                             results.push(TestResult::SupabaseRlsNotEnforced);
                        } else if text.trim() == "[]" {
                             // Empty array means read access allowed, but nothing found.
                             // This is technically RLS "Allowed" (or public), but maybe safe?
                             // Prompt says: "If 401 Unauthorized or 403 Forbidden or [] (empty): Mark as SupabaseRlsEnforced."
                             // Okay, user defined [] as Enforced (Safe/No Data Leak).
                             results.push(TestResult::SupabaseRlsEnforced);
                        } else {
                            // Non-array response?
                             results.push(TestResult::SupabaseRlsNotEnforced);
                        }
                    }
                } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED || resp.status() == reqwest::StatusCode::FORBIDDEN {
                    results.push(TestResult::SupabaseRlsEnforced);
                }
            },
            Err(_) => {
                // Network error or timeout - assume nothing/skip
            }
        }
    }

    results
}
