use reqwest::{Client, header::{HeaderMap, HeaderValue, HeaderName}};
use anyhow::{Result, anyhow};

use log::info;
use url::Url;
use scraper::{Html, Selector};
use crate::scanner::analyzer::headers::{
    analyze_csp, analyze_hsts, analyze_x_content_type_options, analyze_x_frame_options, 
    analyze_permissions_policy, analyze_cross_origin_isolation, analyze_cookies, 
    analyze_referrer_policy, analyze_x_xss_protection
};
use crate::scanner::analyzer::content::analyze_sri;
use crate::scanner::analyzer::cors::analyze_cors;
use crate::scanner::analyzer::vibe_coding::analyze_vibe_coding;
use crate::scanner::analyzer::secrets::analyze_secrets;
use crate::scanner::analyzer::supabase::analyze_supabase;
use crate::scanner::analyzer::cloudflare::analyze_cloudflare;
use crate::scanner::analyzer::broken_components::analyze_broken_components;



use crate::scanner::analyzer::misc::analyze_security_txt;

use crate::scanner::hsts_preload::HstsPreload;
use crate::scanner::grade::TestResult;
use std::str::FromStr;
use std::sync::Arc;
use cookie::Cookie;

pub struct Scanner {
    client: Client,
    client_insecure: Client,
    // We need a client that DOESN'T follow redirects to manually track chain
    client_no_redirect: Client,
    hsts_preload: Arc<HstsPreload>,
    psl: publicsuffix::List,
}


impl Scanner {
    pub fn new() -> Self {
        let mut preload = HstsPreload::new();
        let _ = preload.load_from_file("conf/hsts-preload.json");
        
        let timeout = std::time::Duration::from_secs(30);

        let client = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; HTTP Observatory/1.0; +https://github.com/mozilla/http-observatory)")
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| Client::new());

        let client_insecure = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; HTTP Observatory/1.0; +https://github.com/mozilla/http-observatory)")
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| Client::new());

        // For manual redirect handling
        let client_no_redirect = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; HTTP Observatory/1.0; +https://github.com/mozilla/http-observatory)")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| Client::new());

        // Initialize Public Suffix List
        // Fallback to empty list to ensure basic compilation/runtime without network dependency.
        // Initialize Public Suffix List with checking for common TLDs to avoid panic on empty list
        let psl_data = "com\norg\nnet\nio\nco.uk\ngov\nedu"; 
        let psl: publicsuffix::List = psl_data.parse().unwrap_or_else(|_| Default::default());


        Self {
            client,
            client_insecure,
            client_no_redirect,
            hsts_preload: Arc::new(preload),
            psl,
        }
    }


    pub fn extract_meta_headers(html: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let document = Html::parse_document(html);
        let meta_selector = Selector::parse("meta").unwrap();

        for element in document.select(&meta_selector) {
            if let (Some(http_equiv), Some(content)) = (element.value().attr("http-equiv"), element.value().attr("content")) {
                if let Ok(name) = HeaderName::from_str(http_equiv) {
                    if let Ok(val) = HeaderValue::from_str(content) {
                        headers.insert(name, val);
                    }
                }
            }
        }
        headers
    }
    
    // Returns (Response, ChainHistory, Cookies, IsInsecureFallbackUsed)
    // Returns (Response, ChainHistory, Cookies, IsInsecureFallbackUsed)
    async fn fetch_index_chain(&self, domain: &str) -> Result<(reqwest::Response, Vec<Url>, Vec<Cookie<'static>>, bool), crate::scanner::error::ScannerError> {
        let scheme = "http";
        let start_url = format!("{}://{}", scheme, domain); // Start at HTTP
        let mut url = Url::parse(&start_url).map_err(|e| crate::scanner::error::ScannerError::Request(e.to_string()))?;
        let mut history = Vec::new(); // Track URLs
        let mut cookies = Vec::new();
        let mut max_redirects = 10;
        
        // Try strict chain first
        let current_client = &self.client_no_redirect;
        
        // Loop for manual redirect handling
        loop {
            history.push(url.clone());
            
            // Perform request
            let result = current_client.get(url.clone()).send().await;
            
            match result {
                Ok(response) => {
                    // Extract Cookies
                    for (k, v) in response.headers() {
                        if k == "set-cookie" {
                            if let Ok(s) = v.to_str() {
                                if let Ok(c) = Cookie::parse(s.to_string()) {
                                    cookies.push(c);
                                }
                            }
                        }
                    }

                    if response.status().is_redirection() && max_redirects > 0 {
                        if let Some(loc) = response.headers().get("Location") {
                             if let Ok(loc_str) = loc.to_str() {
                                 // Handle relative redirects
                                 let next_url = url.join(loc_str)?;
                                 url = next_url;
                                 max_redirects -= 1;
                                 continue;
                             }
                        }
                    }
                    
                    // Final response (or stopped following)
                    return Ok((response, history, cookies, false));
                }
                Err(e) => {
                    // Try to map reqwest error to ScannerError
                    return Err(crate::scanner::error::ScannerError::from(e));
                }
            }
        }
    }
    
    // Separate fetch for auxiliary things that don't need chain analysis
    async fn fetch_auxiliary(&self, client: &Client, domain: &str) -> (Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>,
    Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>) {
        let scheme = "http";
        // We usually check these on the FINAL domain? Or original?
        // Let's use original for now, client handles redirects.
        let robots_url = format!("{}://{}/robots.txt", scheme, domain);
        let sitemap_url = format!("{}://{}/sitemap.xml", scheme, domain);
        let crossdomain_url = format!("{}://{}/crossdomain.xml", scheme, domain);
        let clientaccesspolicy_url = format!("{}://{}/clientaccesspolicy.xml", scheme, domain);
        let security_txt_url = format!("{}://{}/.well-known/security.txt", scheme, domain);
        
        // Vibe Coding Probes
        let env_url = format!("{}://{}/.env", scheme, domain);
        let git_url = format!("{}://{}/.git/HEAD", scheme, domain);
        // Checking for a common map file (e.g. main.js.map often doesn't exist at root, but let's try a generic guess or just checks later content)
        // User request says "Found .map files".
        // Robust way: Parse JS files and look for comments. But simple probe:
        // Let's try probing for a sourcemap of a hypothetical bundle, or just return Success if we find ANY map?
        // Actually, let's probe for `main.js.map` as a heuristic, or rely on scanning regex in body for `sourceMappingURL`.
        // The prompt implies we should detecting *exposed* files.
        // Let's Probe `main.js.map` and `app.js.map`.
        // For simplicity in this `fetch_auxiliary` return tuple, let's just add one generic map probe.
        let map_url = format!("{}://{}/main.js.map", scheme, domain);

        tokio::join!(
            client.get(&robots_url).send(),
            client.get(&sitemap_url).send(),
            client.get(&crossdomain_url).send(),
            client.get(&clientaccesspolicy_url).send(),
            client.get(&robots_url) // Placeholder for CORS origin check? reusing logic from old fetch_all. 
                // Old code: client.get(&index_url).header("Origin", ...). 
                // We should probably do CORS check on the main index URL.
                // Let's defer CORS check to after we know the final URL.
                .send(), 
            client.get(&security_txt_url).send(),
            // New Probes
            client.get(&env_url).send(),
            client.get(&git_url).send(),
            client.get(&map_url).send()
        )
    }

    pub async fn scan_site(&self, domain: &str) -> Result<Vec<TestResult>, crate::scanner::error::ScannerError> {
        info!("Starting concurrent fetch for {}", domain);

        // 1. Fetch Index Chain (HTTP -> Redirects -> Final)
        // We do this first to get the final URL for other checks (like CORS)
        let chain_result = self.fetch_index_chain(domain).await; // This is strict
        
        let (response, history, cookies, using_insecure) = match chain_result {
            Ok(res) => res,
            Err(e) => {
                info!("Strict fetch failed: {}", e);
                 // Return the error wrapped
                 return Err(e);
            }
        };

        // If simple fetch, history might just have start.
        
        let mut results = Vec::new();
        // Analyze Redirections from History
        // history[0] is start (http://domain). history[last] is final.
        if let Some(start_url) = history.first() {
             if start_url.scheme() == "http" {
                 // Check if it redirects to HTTPS
                 let final_url = history.last().unwrap();
                 if final_url.scheme() == "https" {
                     results.push(TestResult::RedirectionToHttps);
                     
                     // Check immediate redirect
                     if history.len() > 1 {
                         let first_hop = &history[1];
                         if first_hop.scheme() != "https" {
                             results.push(TestResult::RedirectionNotToHttpsOnInitialRedirection);
                         }
                     }
                 } else {
                     results.push(TestResult::RedirectionMissing); // Or NotToHttps
                 }
                 
                 // Check Off-Host
                 // If any hop is HTTP and Host is different from Start Host
                 let start_host = start_url.host_str().unwrap_or("");
                 let mut off_host = false;
                 // Typically check if the FIRST redirect is off-host before HTTPS.
                 if history.len() > 1 {
                     let first_hop = &history[1];
                      if first_hop.scheme() == "http" && first_hop.host_str().unwrap_or("") != start_host {
                           off_host = true;
                      }
                 }
                 if off_host {
                     results.push(TestResult::RedirectionOffHostFromHttp);
                 }
                 
                 // Check if all redirects are preloaded (Bonus/Parity)
                 // If every host in history having HSTS Preloaded
                 let all_preloaded = history.iter().all(|u| {
                      if let Some(host) = u.host_str() {
                          self.hsts_preload.is_preloaded(host)
                      } else {
                          false
                      }
                 });
                 if all_preloaded {
                     results.push(TestResult::RedirectionAllRedirectsPreloaded);
                 }

             }
        }

        // 2. Fetch Auxiliary (using standard client which follows redirects)
        // We might want to use the final_url from chain for efficiency? 
        // But spec says look at root usually.
        // Let's proceed with parallel fetch of others.
        // We need CORS check on the index page too.
        let final_url = history.last().unwrap().clone();
        
        // Separate CORS prefiight check
        let origin_sent = "http://example.com";
        let cors_preflight = self.client.get(final_url.clone())
            .header("Origin", origin_sent)
            .send().await;

        let (_robots_res, _sitemap_res, cors_res, cap_res, _, security_txt_res, env_res, git_res, map_res) = self.fetch_auxiliary(&self.client, domain).await;

        // Analyze Main Page Content
        if using_insecure {
             results.push(TestResult::RedirectionInvalidCert);
             results.push(TestResult::HstsInvalidCert);
        }
        
        // Clone headers from response
        let mut combined_headers = response.headers().clone();

        // Fetch body to parse meta tags
        let body = response.text().await.unwrap_or_default();
        
        // Parse Meta Tags and Merge
        let meta_headers = Self::extract_meta_headers(&body);
        for (key, value) in meta_headers {
            if let Some(k) = key {
                combined_headers.append(k, value);
            }
        }

        // Header Analysis
        // cookies were collected during chain
        
        // HSTS (needs hsts_active bool for cookies check)
        let mut hsts_result = analyze_hsts(&combined_headers);
        let hsts_active = match hsts_result {
            TestResult::HstsImplementedMaxAgeAtLeastSixMonths | TestResult::HstsImplementedMaxAgeLessThanSixMonths => true, 
            _ => false
        };
        
        if self.hsts_preload.is_preloaded(domain) {
                hsts_result = TestResult::HstsPreloaded;
        }
        results.push(hsts_result);

        // Extract cookies was done in chain
        results.push(analyze_cookies(&cookies, hsts_active));

        // CSP
        let csp_result = analyze_csp(&combined_headers);
        results.push(csp_result); // Pass by value (Copy/Clone enum)? Yes TestResult is Copy

        // Other Headers
        results.push(analyze_referrer_policy(&combined_headers));
        results.push(analyze_x_xss_protection(&combined_headers));
        results.push(analyze_x_content_type_options(&combined_headers));
        
        results.push(analyze_x_frame_options(&combined_headers, &Some(csp_result)));

        // Phase 4: Permissions-Policy & Cross-Origin Isolation
        results.push(analyze_permissions_policy(&combined_headers));
        results.extend(analyze_cross_origin_isolation(&combined_headers));

        // Phase 4: Security.txt
        let sec_status = if let Ok(res) = security_txt_res { res.status() } else { reqwest::StatusCode::NOT_FOUND };
        results.push(analyze_security_txt(sec_status));

use regex::Regex;

        // Phase 5: Vibe Coding Check
        let mut exposed_configs_found = false;
        if let Ok(res) = env_res { 
            if res.status().is_success() { 
                // False positive check: Verify content looks like a .env file (KEY=VALUE)
                if let Ok(text) = res.text().await {
                   // Regex: Start of line, alphanumeric key, equals, value.
                   let env_regex = Regex::new(r"(?m)^[A-Za-z0-9_]+=[^\r\n]*").unwrap();
                   if env_regex.is_match(&text) {
                       exposed_configs_found = true; 
                   }
                }
            } 
        }
        if let Ok(res) = git_res { if res.status().is_success() { exposed_configs_found = true; } }
        
        let mut source_map_file_found = false;
        if let Ok(res) = map_res { 
            if res.status().is_success() { 
                // False positive check: Ensure it's actual JSON and not a Soft 404 HTML page
                if let Ok(text) = res.text().await {
                    // Source maps are JSON objects with a "version" field.
                    // Simple check: Starts with '{' and contains "version".
                    // Regex for robustness: \{"version"\s*:\s*\d
                    let map_regex = Regex::new(r#"(?s)\A\s*\{\s*"version"\s*:\s*\d"#).unwrap();
                    if map_regex.is_match(&text) {
                        source_map_file_found = true; 
                    }
                }
            } 
        }
        
        let mut source_map_ref_found = false;
        if body.contains("sourceMappingURL=") {
            source_map_ref_found = true;
        }

        results.extend(analyze_vibe_coding(&body, exposed_configs_found, source_map_file_found, source_map_ref_found));

        // Content Analysis (SRI)
        results.push(analyze_sri(&body, &final_url, &self.psl));

        // Secrets Analysis
        results.extend(analyze_secrets(&body));

        // Supabase Audit (Async)
        results.extend(analyze_supabase(&body, &self.client).await);

        // Cloudflare Analysis
        results.extend(analyze_cloudflare(&combined_headers));

        // Broken Components / Placeholders
        results.extend(analyze_broken_components(&body));

        // CORS Analysis
        // We need to pass the headers from the CORS preflight request
        let cors_headers = if let Ok(res) = cors_preflight.as_ref() {
            res.headers().clone()
        } else {
            HeaderMap::new()
        };

        let cd_xml = if let Ok(res) = cors_res { res.text().await.ok() } else { None };
        let cap_xml = if let Ok(res) = cap_res { res.text().await.ok() } else { None };

        results.push(analyze_cors(&cors_headers, cd_xml.as_deref(), cap_xml.as_deref(), origin_sent));

        Ok(results)
    }
}
