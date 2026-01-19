use crate::grader::TestResult;
use scraper::{Html, Selector};
use url::Url;

pub fn analyze_sri(html_content: &str, final_url: &Url) -> TestResult {
    let document = Html::parse_document(html_content);
    let script_selector = Selector::parse("script").unwrap();
    
    let mut scripts_found = false;
    let mut scripts_external_insecure = false;
    let mut all_external_sri = true;
    let mut all_secure_origin = true;

    for element in document.select(&script_selector) {
        scripts_found = true;
        
        if let Some(src) = element.value().attr("src") {
             // Check if external
             if let Ok(src_url) = final_url.join(src) {
                 if src_url.scheme() == "http" {
                      scripts_external_insecure = true;
                 }
                 
                 // If different host (rough approximation without PSL)
                 if src_url.host_str() != final_url.host_str() {
                     all_secure_origin = false;
                     // Check integrity
                     if element.value().attr("integrity").is_none() {
                         all_external_sri = false;
                     }
                 }
             }
        }
    }

    if !scripts_found {
         TestResult::SriNotImplementedButNoScriptsLoaded
    } else if scripts_external_insecure {
         TestResult::SriNotImplementedAndExternalScriptsNotLoadedSecurely
    } else if all_secure_origin {
         TestResult::SriNotImplementedButAllScriptsLoadedFromSecureOrigin
    } else if all_external_sri {
         TestResult::SriImplementedAndExternalScriptsLoadedSecurely
    } else {
         TestResult::SriNotImplementedButExternalScriptsLoadedSecurely // Simplified logic
    }
}
