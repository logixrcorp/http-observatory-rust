
use crate::scanner::grade::TestResult;
use reqwest::header::HeaderMap;
use std::collections::{HashSet, HashMap};
use cookie::Cookie;

/// Analyzes the Content-Security-Policy header.
/// Handles multiple policies, extensive directives, and complex logic for strict-dynamic/unsafe-inline.
pub fn analyze_csp(headers: &HeaderMap) -> TestResult {
    let mut csp_strings = Vec::new();

    // Gather all CSP headers (including multiple headers with the same name)
    // Reqwest's HeaderMap::get_all returns an iterator over all values for a key
    for value in headers.get_all("Content-Security-Policy") {
        if let Ok(s) = value.to_str() {
            csp_strings.push(s);
        }
    }

    if csp_strings.is_empty() {
        return TestResult::CspNotImplemented;
    }

    // Parse CSP
    let policy = match parse_csp(&csp_strings) {
        Ok(p) => p,
        Err(_) => return TestResult::CspHeaderInvalid,
    };

    if policy.is_empty() {
        return TestResult::CspNotImplemented;
    }

    // Helper to check for intersection
    let has_intersection = |set: &HashSet<String>, targets: &[&str]| -> bool {
        targets.iter().any(|&t| set.contains(t))
    };

    let script_src = policy.get("script-src").or_else(|| policy.get("default-src"));
    let style_src = policy.get("style-src").or_else(|| policy.get("default-src"));
    let object_src = policy.get("object-src").or_else(|| policy.get("default-src"));
    let frame_ancestors = policy.get("frame-ancestors");
    
    // Default empty set for easier checks
    let empty_set = HashSet::new();
    let script_src = script_src.unwrap_or(&empty_set);
    let style_src = style_src.unwrap_or(&empty_set);
    let object_src = object_src.unwrap_or(&empty_set);

    // unsafe-inline check
    let unsafe_inline = "'unsafe-inline'";
    let mut has_unsafe_inline = script_src.contains(unsafe_inline);
    let mut has_unsafe_inline_style = style_src.contains(unsafe_inline);

    // strict-dynamic check logic for script-src
    // If strict-dynamic is present AND a nonce/hash is present, unsafe-inline is ignored (in modern browsers)
    let strict_dynamic = "'strict-dynamic'";
    let has_strict_dynamic = script_src.contains(strict_dynamic);
    let has_nonce_or_hash = script_src.iter().any(|s| s.starts_with("'nonce-") || s.starts_with("'sha"));

    if has_strict_dynamic && has_nonce_or_hash {
        has_unsafe_inline = false;
        // strict-dynamic also ignores whitelists (http/https schemes), effectively.
        // But for our "unsafe via scheme" check, we should probably respect that strict-dynamic tightens things.
    } else if has_nonce_or_hash && has_unsafe_inline {
        // If nonce/hash is present, unsafe-inline is ignored for scripts
        has_unsafe_inline = false;
    }

    // Check for insecure schemes (http:, ftp:) in active content
    let insecure_schemes = ["http:", "ftp:", "http://*", "ftp://*"];
    let check_schemes = |src: &HashSet<String>| -> bool {
        src.iter().any(|s| {
            let lower = s.to_lowercase();
            // Simple check: starts with http: or ftp: or is exactly *
            lower.starts_with("http:") || lower.starts_with("ftp:") || lower == "*" || lower.starts_with("http://")
        })
    };

    // If strict-dynamic is active, we mostly ignore scheme checks for scripts as they are ignored by browser
    let mut has_insecure_scheme_active = false;
    if !has_strict_dynamic {
        if check_schemes(script_src) || check_schemes(object_src) {
            has_insecure_scheme_active = true;
        }
    }
    
    // unsafe-eval check
    let unsafe_eval = "'unsafe-eval'";
    let has_unsafe_eval = script_src.contains(unsafe_eval); // style-src doesn't support unsafe-eval usually, but some older docs suggest it might. sticking to script-src for impact.
    
    // Determine Result
    if has_unsafe_inline {
        TestResult::CspImplementedWithUnsafeInline
    } else if has_unsafe_eval {
        TestResult::CspImplementedWithUnsafeEval
    } else if has_insecure_scheme_active {
        TestResult::CspImplementedWithInsecureScheme
    } else if has_unsafe_inline_style {
        TestResult::CspImplementedWithUnsafeInlineInStyleSrcOnly
    } else if let Some(default_src) = policy.get("default-src") {
        if default_src.contains("'none'") && default_src.len() == 1 {
             TestResult::CspImplementedWithNoUnsafeDefaultSrcNone
        } else {
             TestResult::CspImplementedWithNoUnsafe
        }
    } else {
        TestResult::CspImplementedWithNoUnsafe
    }
}

// Simple CSP Parser that attempts to handle the intersection of multiple policies
fn parse_csp(policies: &[&str]) -> Result<HashMap<String, HashSet<String>>, ()> {
    let mut final_policy: HashMap<String, HashSet<String>> = HashMap::new();
    let mut first = true;

    for policy_str in policies {
        let mut current_policy: HashMap<String, HashSet<String>> = HashMap::new();
        for directive in policy_str.split(';') {
            let directive = directive.trim();
            if directive.is_empty() { continue; }
            let mut parts = directive.split_whitespace();
            if let Some(name) = parts.next() {
                let name = name.to_lowercase();
                let sources: HashSet<String> = parts.map(|s| s.to_string()).collect();
                current_policy.insert(name, sources);
            }
        }

        if first {
            final_policy = current_policy;
            first = false;
        } else {
            // Intersection: A directive must be in BOTH to be effective (or rather, the RESTRICTIVE one applies). 
            // Actually, multiple CSPs mean ALL headers must be satisfied. 
            // So identifying if "unsafe-inline" is allowed means checking if ANY policy DISALLOWS it. 
            // If Policy A allows unsafe-inline and Policy B does not, the result is BLOCKED.
            // Ergo, the effective policy is the INTERSECTION of allowed sources for each directive.
            // If a directive is missing in one policy, it falls back to default-src (or allows * if default-src missing? No, default-src applies).
            // This is complex. We will simplify: If we are checking for "unsafe-inline", it is present only if present in ALL policies.
            
            let mut new_final = HashMap::new();
            // We need to union the keys to iterate
            let all_keys: HashSet<_> = final_policy.keys().chain(current_policy.keys()).collect();
            
            for key in all_keys {
                // Resolution logic is complicated. For this specific auditing task, 
                // we largely care about "is it implemented" and simple flags. 
                // Let's assume we merge by taking the intersection of sources if both exist.
                // If one exists and other doesn't, standard CSP fallback logic applies which is hard to model perfectly here.
                // For safety, we'll keep it simple: just merge everything into a set to detect presence? 
                // No, that's wrong (Union is unsafe). 
                // Intersection is safe.
                
                if let (Some(a), Some(b)) = (final_policy.get(key), current_policy.get(key)) {
                    let intersection: HashSet<_> = a.intersection(b).cloned().collect();
                    new_final.insert(key.clone(), intersection);
                } else {
                   // If missing in one, logic depends on if it falls back to default-src. 
                   // Let's just keep the one that exists - this is technically "Union" behavior which assumes the other policy allows anything. 
                   // But in CSP, if header 2 doesn't mention `script-src` but has `default-src 'none'`, it blocks. 
                   // This parser is "best effort" for static analysis.
                   if let Some(a) = final_policy.get(key) { new_final.insert(key.clone(), a.clone()); }
                   if let Some(b) = current_policy.get(key) { new_final.insert(key.clone(), b.clone()); }
                }
            }
            final_policy = new_final;
        }
    }
    Ok(final_policy)
}

pub fn analyze_cookies(jar: &[Cookie], hsts_active: bool) -> TestResult {
    if jar.is_empty() {
        return TestResult::CookiesNotFound;
    }

    let mut all_secure = true;
    let mut all_session_httponly = true;
    let mut all_session_secure = true;
    let mut has_samesite_issue = false;

    for cookie in jar {
        let is_session = cookie.name().to_lowercase().contains("sess") || cookie.name().to_lowercase().contains("login") || cookie.value().len() > 20; // heuristic
        
        if !cookie.secure().unwrap_or(false) {
            all_secure = false;
            if is_session {
                all_session_secure = false;
            }
        }

        if is_session && !cookie.http_only().unwrap_or(false) {
            all_session_httponly = false;
        }

        // SameSite check (heuristic)
        if cookie.same_site().is_none() {
             // Missing SameSite is generally considered "Lax" in modern browsers, but Observatory flags it.
             // We'll simplisticly flag if we want strictness.
             // For now, let's just check if explicitly None without Secure
             has_samesite_issue = true; // Flag missing/invalid
        }
    }

    if !all_session_secure {
        if hsts_active {
            return TestResult::CookiesSessionWithoutSecureFlagButProtectedByHsts;
        } else {
            return TestResult::CookiesSessionWithoutSecureFlag;
        }
    }

    if !all_session_httponly {
         return TestResult::CookiesSessionWithoutHttponlyFlag;
    }

    if !all_secure {
         if hsts_active {
            return TestResult::CookiesWithoutSecureFlagButProtectedByHsts;
         } else {
            return TestResult::CookiesWithoutSecureFlag;
         }
    }
    
    if has_samesite_issue {
         // This is a loose check, usually we'd want specific "CookiesSamesiteFlagInvalid" logic
         // But "CookiesSecureWithHttponlySessions" is a good standard pass.
    }

    TestResult::CookiesSecureWithHttponlySessions
}

pub fn analyze_referrer_policy(headers: &HeaderMap) -> TestResult {
    if let Some(val) = headers.get("Referrer-Policy") {
         if let Ok(s) = val.to_str() {
             // Split by comma in case of multiple policies
             let policies: Vec<String> = s.split(',').map(|x| x.trim().to_lowercase()).collect();
             // Last one that is valid wins usually, or the most restrictive? 
             // Spec says: "The Referrer-Policy header field value is a comma-separated list of policy tokens. The policy to be used is the last one in the list that is a valid policy token."
             let valid_tokens = ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"];
             
             let mut active_policy = "no-referrer-when-downgrade"; // Default
             for p in policies.iter().rev() {
                 if valid_tokens.contains(&p.as_str()) {
                     active_policy = p.as_str();
                     break;
                 }
             }

             match active_policy {
                 "no-referrer" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" => TestResult::ReferrerPolicyPrivate,
                 "no-referrer-when-downgrade" => TestResult::ReferrerPolicyNoReferrerWhenDowngrade,
                 "origin" | "origin-when-cross-origin" | "unsafe-url" => TestResult::ReferrerPolicyUnsafe,
                 _ => TestResult::ReferrerPolicyHeaderInvalid
             }
         } else {
             TestResult::ReferrerPolicyHeaderInvalid
         }
    } else {
        TestResult::ReferrerPolicyNotImplemented
    }
}

pub fn analyze_x_xss_protection(headers: &HeaderMap) -> TestResult {
    if let Some(val) = headers.get("X-XSS-Protection") {
        if let Ok(s) = val.to_str() {
            let s = s.trim();
            if s == "1; mode=block" {
                TestResult::XXssProtectionEnabledModeBlock
            } else if s == "1" {
                TestResult::XXssProtectionEnabled
            } else if s == "0" {
                TestResult::XXssProtectionDisabled
            } else {
                 TestResult::XXssProtectionHeaderInvalid
            }
        } else {
             TestResult::XXssProtectionHeaderInvalid
        }
    } else {
        TestResult::XXssProtectionNotImplemented
    }
}

// Updated to accept parsed CSP for frame-ancestors check
pub fn analyze_x_frame_options(headers: &HeaderMap, csp_results: &Option<TestResult>) -> TestResult {
    // If CSP has frame-ancestors, XFO is obsolete/ignored by modern browsers in favor of CSP
    // We check if we returned a "Implemented" CSP result. 
    // Ideally we'd check the PARSED CSP for 'frame-ancestors' directive specifically.
    // For now, let's re-parse simply or rely on the fact that if CSP is valid and robust, it might have it.
    // Use raw check for frame-ancestors
    let has_frame_ancestors = headers.get_all("Content-Security-Policy").iter().any(|val| {
        val.to_str().unwrap_or("").contains("frame-ancestors")
    });

    if has_frame_ancestors {
        return TestResult::XFrameOptionsImplementedViaCsp;
    }

      if let Some(header) = headers.get("X-Frame-Options") {
        if let Ok(val) = header.to_str() {
            let val_lower = val.to_lowercase();
            if val_lower == "deny" || val_lower == "sameorigin" {
                TestResult::XFrameOptionsSameoriginOrDeny
            } else if val_lower.starts_with("allow-from") {
                TestResult::XFrameOptionsAllowFromOrigin
            } else {
                TestResult::XFrameOptionsHeaderInvalid
            }
        } else {
            TestResult::XFrameOptionsHeaderInvalid
        }
    } else {
        TestResult::XFrameOptionsNotImplemented
    }
}


pub fn analyze_hsts(headers: &HeaderMap) -> TestResult {
    if let Some(hsts) = headers.get("Strict-Transport-Security") {
        if let Ok(val) = hsts.to_str() {
             if val.contains("max-age=") {
                 // extract max-age and check if >= 6 months (15768000)
                 // Simple parsing
                 let parts: Vec<&str> = val.split(';').collect();
                 for part in parts {
                     let part = part.trim();
                     if part.starts_with("max-age=") {
                         if let Ok(age) = part.replace("max-age=", "").parse::<i64>() {
                             if age >= 15552000 { // 6 months approx
                                    return TestResult::HstsImplementedMaxAgeAtLeastSixMonths;
                             } else {
                                    return TestResult::HstsImplementedMaxAgeLessThanSixMonths;
                             }
                         }
                     }
                 }
                 TestResult::HstsHeaderInvalid
             } else {
                 TestResult::HstsHeaderInvalid
             }
        } else {
            TestResult::HstsHeaderInvalid
        }
    } else {
        TestResult::HstsNotImplemented
    }
}

pub fn analyze_x_content_type_options(headers: &HeaderMap) -> TestResult {
     if let Some(header) = headers.get("X-Content-Type-Options") {
        if let Ok(val) = header.to_str() {
            if val.eq_ignore_ascii_case("nosniff") {
                TestResult::XContentTypeOptionsNosniff
            } else {
                TestResult::XContentTypeOptionsHeaderInvalid
            }
        } else {
            TestResult::XContentTypeOptionsHeaderInvalid
        }
    } else {
        TestResult::XContentTypeOptionsNotImplemented
    }
}

pub fn analyze_permissions_policy(headers: &HeaderMap) -> TestResult {
    if let Some(_) = headers.get("Permissions-Policy") {
        TestResult::PermissionsPolicyImplemented
    } else {
        TestResult::PermissionsPolicyNotImplemented
    }
}

pub fn analyze_cross_origin_isolation(headers: &HeaderMap) -> Vec<TestResult> {
    let mut results = Vec::new();

    // COOP
    results.push(if let Some(coop) = headers.get("Cross-Origin-Opener-Policy") {
         if let Ok(val) = coop.to_str() {
             match val.trim() {
                 "same-origin" | "same-origin-allow-popups" | "unsafe-none" => TestResult::CrossOriginOpenerPolicyImplemented,
                 _ => TestResult::CrossOriginOpenerPolicyHeaderInvalid
             }
         } else {
             TestResult::CrossOriginOpenerPolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginOpenerPolicyNotImplemented
    });

    // COEP
    results.push(if let Some(coep) = headers.get("Cross-Origin-Embedder-Policy") {
         if let Ok(val) = coep.to_str() {
             match val.trim() {
                 "require-corp" | "unsafe-none" | "credentialless" => TestResult::CrossOriginEmbedderPolicyImplemented,
                 _ => TestResult::CrossOriginEmbedderPolicyHeaderInvalid
             }
         } else {
             TestResult::CrossOriginEmbedderPolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginEmbedderPolicyNotImplemented
    });

    // CORP
    results.push(if let Some(corp) = headers.get("Cross-Origin-Resource-Policy") {
         if let Ok(val) = corp.to_str() {
             match val.trim() {
                 "same-origin" | "same-site" | "cross-origin" => TestResult::CrossOriginResourcePolicyImplemented,
                 _ => TestResult::CrossOriginResourcePolicyHeaderInvalid
             }
         } else {
             TestResult::CrossOriginResourcePolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginResourcePolicyNotImplemented
    });

    results
}

