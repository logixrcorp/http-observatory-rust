use crate::grader::TestResult;
use reqwest::header::HeaderMap;

pub fn analyze_csp(headers: &HeaderMap) -> TestResult {
    if let Some(csp_header) = headers.get("Content-Security-Policy") {
       match csp_header.to_str() {
           Ok(val) => {
               if val.contains("unsafe-inline") {
                   TestResult::CspImplementedWithUnsafeInline
               } else if val.contains("default-src 'none'") {
                   TestResult::CspImplementedWithNoUnsafeDefaultSrcNone
               } else {
                   TestResult::CspImplementedWithNoUnsafe
               }
           },
           Err(_) => TestResult::CspHeaderInvalid
       }
    } else {
        TestResult::CspNotImplemented
    }
}

pub fn analyze_hsts(headers: &HeaderMap) -> TestResult {
    if let Some(hsts) = headers.get("Strict-Transport-Security") {
        if let Ok(val) = hsts.to_str() {
             if val.contains("max-age=") {
                 TestResult::HstsImplementedMaxAgeAtLeastSixMonths
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

pub fn analyze_x_frame_options(headers: &HeaderMap) -> TestResult {
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
         if let Ok(_) = coop.to_str() {
             TestResult::CrossOriginOpenerPolicyImplemented
         } else {
             TestResult::CrossOriginOpenerPolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginOpenerPolicyNotImplemented
    });

    // COEP
    results.push(if let Some(coep) = headers.get("Cross-Origin-Embedder-Policy") {
         if let Ok(_) = coep.to_str() {
             TestResult::CrossOriginEmbedderPolicyImplemented
         } else {
             TestResult::CrossOriginEmbedderPolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginEmbedderPolicyNotImplemented
    });

    // CORP
    results.push(if let Some(corp) = headers.get("Cross-Origin-Resource-Policy") {
         if let Ok(_) = corp.to_str() {
             TestResult::CrossOriginResourcePolicyImplemented
         } else {
             TestResult::CrossOriginResourcePolicyHeaderInvalid
         }
    } else {
        TestResult::CrossOriginResourcePolicyNotImplemented
    });

    results
}
