use crate::grader::TestResult;
use reqwest::header::HeaderMap;
use scraper::{Html, Selector};

pub fn analyze_cors(cors_headers: &HeaderMap, crossdomain_xml: Option<&str>, cap_xml: Option<&str>) -> TestResult {
    let mut universal_access = false;
    let mut restricted_access = false;
    let mut public_access = false;
    let mut _implemented = false;

    // Check ACAO Header
    if let Some(acao) = cors_headers.get("Access-Control-Allow-Origin") {
        if let Ok(val) = acao.to_str() {
            _implemented = true;
            if val.trim() == "*" {
                public_access = true;
            } else {
                restricted_access = true;
                // Check if universal (Origin reflection) - complex to simulate without multiple requests
            }
        }
    }

    // Check crossdomain.xml
    if let Some(xml) = crossdomain_xml {
        let document = Html::parse_fragment(xml); // Use fragment for loose XML
        let selector = Selector::parse("allow-access-from").unwrap();
        for element in document.select(&selector) {
            _implemented = true;
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
            _implemented = true;
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
