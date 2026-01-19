use reqwest::{Client, header::{HeaderMap, HeaderValue, HeaderName}};
use crate::analyzer::headers::{analyze_csp, analyze_hsts, analyze_x_content_type_options, analyze_x_frame_options, analyze_permissions_policy, analyze_cross_origin_isolation};
use crate::analyzer::content::analyze_sri;
use crate::analyzer::cors::analyze_cors;
use crate::analyzer::misc::analyze_security_txt;
use crate::analyzer::hsts_preload::HstsPreload;
use crate::grader::{TestResult, Grade};
use crate::models::{ScanResult, TlsResult};
use crate::analyzer::tls::analyze_tls;
use crate::scanner::active::active_scan;
use log::info;
use scraper::{Html, Selector};
use std::str::FromStr;
use std::sync::Arc;
use url::Url;
use anyhow::{anyhow, Result};

pub struct Scanner {
    client: Client,
    client_insecure: Client,
    hsts_preload: Arc<HstsPreload>,
    active_enabled: bool,
}

impl Scanner {
    pub fn new(active_enabled: bool) -> Self {
        let mut preload = HstsPreload::new();
        let _ = preload.load_from_file("conf/hsts-preload.json");

        let client = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; HTTP Observatory/1.0; +https://github.com/mozilla/http-observatory)")
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        let client_insecure = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; HTTP Observatory/1.0; +https://github.com/mozilla/http-observatory)")
            .redirect(reqwest::redirect::Policy::limited(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            client_insecure,
            hsts_preload: Arc::new(preload),
            active_enabled,
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

    async fn fetch_all(&self, client: &Client, start_url: &Url) -> (Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>, Result<reqwest::Response, reqwest::Error>) {
        let index_url = start_url.to_string();
        let robots_url = start_url.join("/robots.txt").unwrap().to_string();
        let sitemap_url = start_url.join("/sitemap.xml").unwrap().to_string();
        let crossdomain_url = start_url.join("/crossdomain.xml").unwrap().to_string();
        let clientaccesspolicy_url = start_url.join("/clientaccesspolicy.xml").unwrap().to_string();
        let security_txt_url = start_url.join("/.well-known/security.txt").unwrap().to_string();

        tokio::join!(
            client.get(&index_url).send(),
            client.get(&robots_url).send(),
            client.get(&sitemap_url).send(),
            client.get(&crossdomain_url).send(),
            client.get(&clientaccesspolicy_url).send(),
             client.get(&index_url)
                .header("Origin", "http://example.com")
                .send(),
            client.get(&security_txt_url).send()
        )
    }

    // Note: extract_meta_headers and fetch_all remain, but fetch_all needs to include security_txt_url if not already added in previous steps.
    // Assuming fetch_all was updated in previous steps or I should verify. 
    // Wait, I see fetch_all in the file content, it was updated in Step Id: 535 to include security_txt.
    
    pub async fn scan_site(&self, start_url: &Url) -> Result<ScanResult> {
        let domain = start_url.host_str().unwrap_or("unknown").to_string();
        info!("Starting concurrent fetch for {}", start_url);

        let fetch_future = async {
            let mut fetch_results = self.fetch_all(&self.client, start_url).await;
            if fetch_results.0.is_err() {
                info!("Strict fetch failed for {}, retrying...", start_url);
                fetch_results = self.fetch_all(&self.client_insecure, start_url).await;
            }
            fetch_results
        };

        let tls_future = async {
             let d = domain.to_string();
             tokio::task::spawn_blocking(move || analyze_tls(&d)).await.unwrap_or_else(|e| TlsResult { protocol: "Error".into(), cipher: "Error".into(), is_secure: false, issues: vec![e.to_string()] })
        };

        let active_future = async {
            if self.active_enabled {
                Some(active_scan(&domain).await)
            } else {
                None
            }
        };

        let (fetch_results, tls_result, active_result) = tokio::join!(fetch_future, tls_future, active_future);
        
        let (index_res, _robots_res, _sitemap_res, cors_res, cap_res, cors_preflight_res, security_txt_res) = fetch_results;
        
        let mut results = Vec::new();

        match index_res {
            Ok(response) => {
                let final_url = Url::parse(response.url().as_str()).unwrap_or_else(|_| start_url.clone());
                
                let mut combined_headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                let meta_headers = Self::extract_meta_headers(&body);
                for (key, value) in meta_headers {
                    if let Some(k) = key { combined_headers.append(k, value); }
                }

                results.push(analyze_csp(&combined_headers));
                
                let mut hsts_result = analyze_hsts(&combined_headers);
                if self.hsts_preload.is_preloaded(&domain) { hsts_result = TestResult::HstsPreloaded; }
                results.push(hsts_result);

                results.push(analyze_x_content_type_options(&combined_headers));
                results.push(analyze_x_frame_options(&combined_headers));
                results.push(analyze_permissions_policy(&combined_headers));
                results.extend(analyze_cross_origin_isolation(&combined_headers));

                let sec_status = if let Ok(res) = security_txt_res { res.status() } else { reqwest::StatusCode::NOT_FOUND };
                results.push(analyze_security_txt(sec_status));

                results.push(analyze_sri(&body, &final_url));

                let cors_headers = if let Ok(res) = cors_preflight_res.as_ref() { res.headers().clone() } else { HeaderMap::new() };
                let cd_xml = if let Ok(res) = cors_res { res.text().await.ok() } else { None };
                let cap_xml = if let Ok(res) = cap_res { res.text().await.ok() } else { None };

                results.push(analyze_cors(&cors_headers, cd_xml.as_deref(), cap_xml.as_deref()));
            }
            Err(e) => {
                return Err(anyhow!("Site down: {}", e));
            }
        }

        // Calculate Score
        let mut score: i16 = 100;
        for r in &results {
            score = score.saturating_add(r.modifier());
        }
        
        if !tls_result.is_secure {
            score = score.saturating_sub(20);
        }
        
        score = score.clamp(0, 100);
        let grade = Grade::from_score(score);

        Ok(ScanResult {
            domain: domain.to_string(),
            score,
            grade: grade.to_string(),
            test_results: results,
            tls_result,
            active_result,
        })
    }
}
