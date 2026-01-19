use crate::scanner::grade::TestResult;
use reqwest::header::HeaderMap;
use scraper::{Html, Selector};

pub fn analyze_cors(cors_headers: &HeaderMap, crossdomain_xml: Option<&str>, cap_xml: Option<&str>, origin_sent: &str) -> TestResult {
    let mut universal_access = false;
    let mut restricted_access = false;
    let mut public_access = false;
    let mut implemented = false;

    // Check ACAO Header
    if let Some(acao) = cors_headers.get("Access-Control-Allow-Origin") {
        if let Ok(val) = acao.to_str() {
            implemented = true;
            if val.trim() == "*" {
                public_access = true;
            } else if val.trim() == origin_sent {
                 // Reflected origin. Check Credentials.
                 if let Some(acac) = cors_headers.get("Access-Control-Allow-Credentials") {
                     if let Ok(c_val) = acac.to_str() {
                         if c_val.trim().eq_ignore_ascii_case("true") {
                             universal_access = true;
                         }
                     }
                 }
                 // If reflected but no credentials, it's restricted/safe-ish for universal access grade?
                 // Or typically just considered restricted.
                 if !universal_access {
                     restricted_access = true; 
                 }
            } else {
                restricted_access = true;
            }
        }
    }

    // Check crossdomain.xml
    if let Some(xml) = crossdomain_xml {
        let document = Html::parse_fragment(xml); // Use fragment for loose XML
        let selector = Selector::parse("allow-access-from").unwrap();
        for element in document.select(&selector) {
            implemented = true;
            if let Some(domain) = element.value().attr("domain") {
                if domain.trim() == "*" {
                     universal_access = true;
                } else {
                     restricted_access = true;
                }
            }
        }
    }

    // Check clientaccesspolicy.xml
    if let Some(xml) = cap_xml {
        let document = Html::parse_fragment(xml);
        let selector = Selector::parse("domain").unwrap();
        for element in document.select(&selector) {
            implemented = true;
            if let Some(uri) = element.value().attr("uri") {
                 if uri.trim() == "*" {
                     universal_access = true;
                 } else {
                     restricted_access = true;
                }
            }
        }
    }

    if public_access {
        TestResult::CorsImplementedWithPublicAccess
    } else if universal_access {
        TestResult::CorsImplementedWithUniversalAccess
    } else if restricted_access {
        TestResult::CorsImplementedWithRestrictedAccess
    } else {
        TestResult::CorsNotImplemented
    }
}
