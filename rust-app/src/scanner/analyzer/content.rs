use crate::scanner::grade::TestResult;
use scraper::{Html, Selector};
use url::Url;
use publicsuffix::Psl;





pub fn analyze_sri(html_content: &str, final_url: &Url, psl: &publicsuffix::List) -> TestResult {
    let document = Html::parse_document(html_content);
    let script_selector = Selector::parse("script").unwrap();
    
    // Determine SLD of final_url
    // Simplified SLD extraction (fallback since publicsuffix crate API is elusive)
    

    let mut scripts_found = false;
    let mut scripts_external_insecure = false;
    let mut all_external_sri = true;
    let mut all_secure_origin = true;

    // Use PSL to extract root domain (SLD)
    let doc_domain = psl.domain(final_url.host_str().unwrap_or("").as_bytes());


    for element in document.select(&script_selector) {
        scripts_found = true;
        
        if let Some(src) = element.value().attr("src") {
             // Check if external
             if let Ok(src_url) = final_url.join(src) {
                 if src_url.scheme() == "http" {
                      scripts_external_insecure = true;
                 }
                 
                 // Check if it's the same root domain
                 let src_host_str = src_url.host_str().unwrap_or("");
                 let is_same_root = if let Some(ref root) = doc_domain {
                     if let Some(src_parsed) = psl.domain(src_host_str.as_bytes()) {
                         src_parsed == *root
                     } else {
                         false
                     }
                 } else {
                     src_url.host_str() == final_url.host_str()
                 };

                 if !is_same_root {
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
         TestResult::SriImplementedButExternalScriptsNotLoadedSecurely 
         // Logic fix: if all_external_sri is false, then NOT all scripts are loaded securely.
         // Wait, the original Python logic:
         /*
            if not all_external_sri:
                return 'sri-implemented-but-external-scripts-not-loaded-securely'
         */
    }
}

