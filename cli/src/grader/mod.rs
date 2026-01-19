use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, EnumIter};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
pub enum Grade {
    #[strum(serialize = "A+")]
    APlus,
    #[strum(serialize = "A")]
    A,
    #[strum(serialize = "A-")]
    AMinus,
    #[strum(serialize = "B+")]
    BPlus,
    #[strum(serialize = "B")]
    B,
    #[strum(serialize = "B-")]
    BMinus,
    #[strum(serialize = "C+")]
    CPlus,
    #[strum(serialize = "C")]
    C,
    #[strum(serialize = "C-")]
    CMinus,
    #[strum(serialize = "D+")]
    DPlus,
    #[strum(serialize = "D")]
    D,
    #[strum(serialize = "D-")]
    DMinus,
    #[strum(serialize = "F")]
    F,
}

impl Grade {
    pub fn from_score(score: i16) -> Self {
        let score = score.max(0);
        // Map score to grade logic
        if score >= 100 { Grade::APlus }
        else if score >= 90 { Grade::A }
        else if score >= 85 { Grade::AMinus }
        else if score >= 80 { Grade::BPlus }
        else if score >= 75 { Grade::B }
        else if score >= 70 { Grade::BMinus }
        else if score >= 65 { Grade::CPlus }
        else if score >= 60 { Grade::C }
        else if score >= 55 { Grade::CMinus }
        else if score >= 50 { Grade::DPlus }
        else if score >= 45 { Grade::D }
        else if score >= 40 { Grade::DMinus }
        else { Grade::F }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum TestResult {
    // CSP
    #[strum(serialize = "csp-implemented-with-no-unsafe-default-src-none")]
    CspImplementedWithNoUnsafeDefaultSrcNone,
    #[strum(serialize = "csp-implemented-with-no-unsafe")]
    CspImplementedWithNoUnsafe,
    #[strum(serialize = "csp-implemented-with-unsafe-inline-in-style-src-only")]
    CspImplementedWithUnsafeInlineInStyleSrcOnly,
    #[strum(serialize = "csp-implemented-with-insecure-scheme-in-passive-content-only")]
    CspImplementedWithInsecureSchemeInPassiveContentOnly,
    #[strum(serialize = "csp-implemented-with-unsafe-eval")]
    CspImplementedWithUnsafeEval,
    #[strum(serialize = "csp-implemented-with-unsafe-inline")]
    CspImplementedWithUnsafeInline,
    #[strum(serialize = "csp-implemented-with-insecure-scheme")]
    CspImplementedWithInsecureScheme,
    #[strum(serialize = "csp-header-invalid")]
    CspHeaderInvalid,
    #[strum(serialize = "csp-not-implemented")]
    CspNotImplemented,

    // Cookies
    #[strum(serialize = "cookies-secure-with-httponly-sessions-and-samesite")]
    CookiesSecureWithHttponlySessionsAndSamesite,
    #[strum(serialize = "cookies-secure-with-httponly-sessions")]
    CookiesSecureWithHttponlySessions,
    #[strum(serialize = "cookies-not-found")]
    CookiesNotFound,
    #[strum(serialize = "cookies-without-secure-flag-but-protected-by-hsts")]
    CookiesWithoutSecureFlagButProtectedByHsts,
    #[strum(serialize = "cookies-session-without-secure-flag-but-protected-by-hsts")]
    CookiesSessionWithoutSecureFlagButProtectedByHsts,
    #[strum(serialize = "cookies-without-secure-flag")]
    CookiesWithoutSecureFlag,
    #[strum(serialize = "cookies-samesite-flag-invalid")]
    CookiesSamesiteFlagInvalid,
    #[strum(serialize = "cookies-anticsrf-without-samesite-flag")]
    CookiesAnticsrfWithoutSamesiteFlag,
    #[strum(serialize = "cookies-session-without-httponly-flag")]
    CookiesSessionWithoutHttponlyFlag,
    #[strum(serialize = "cookies-session-without-secure-flag")]
    CookiesSessionWithoutSecureFlag,

    // CORS
    #[strum(serialize = "cross-origin-resource-sharing-not-implemented")]
    CorsNotImplemented,
    #[strum(serialize = "cross-origin-resource-sharing-implemented-with-public-access")]
    CorsImplementedWithPublicAccess,
    #[strum(serialize = "cross-origin-resource-sharing-implemented-with-restricted-access")]
    CorsImplementedWithRestrictedAccess,
    #[strum(serialize = "cross-origin-resource-sharing-implemented-with-universal-access")]
    CorsImplementedWithUniversalAccess,

    // Redirection
    #[strum(serialize = "redirection-all-redirects-preloaded")]
    RedirectionAllRedirectsPreloaded,
    #[strum(serialize = "redirection-to-https")]
    RedirectionToHttps,
    #[strum(serialize = "redirection-not-needed-no-http")]
    RedirectionNotNeededNoHttp,
    #[strum(serialize = "redirection-off-host-from-http")]
    RedirectionOffHostFromHttp,
    #[strum(serialize = "redirection-not-to-https-on-initial-redirection")]
    RedirectionNotToHttpsOnInitialRedirection,
    #[strum(serialize = "redirection-not-to-https")]
    RedirectionNotToHttps,
    #[strum(serialize = "redirection-missing")]
    RedirectionMissing,
    #[strum(serialize = "redirection-invalid-cert")]
    RedirectionInvalidCert,

    // Referrer Policy
    #[strum(serialize = "referrer-policy-private")]
    ReferrerPolicyPrivate,
    #[strum(serialize = "referrer-policy-no-referrer-when-downgrade")]
    ReferrerPolicyNoReferrerWhenDowngrade,
    #[strum(serialize = "referrer-policy-not-implemented")]
    ReferrerPolicyNotImplemented,
    #[strum(serialize = "referrer-policy-unsafe")]
    ReferrerPolicyUnsafe,
    #[strum(serialize = "referrer-policy-header-invalid")]
    ReferrerPolicyHeaderInvalid,

    // HSTS
    #[strum(serialize = "hsts-preloaded")]
    HstsPreloaded,
    #[strum(serialize = "hsts-implemented-max-age-at-least-six-months")]
    HstsImplementedMaxAgeAtLeastSixMonths,
    #[strum(serialize = "hsts-implemented-max-age-less-than-six-months")]
    HstsImplementedMaxAgeLessThanSixMonths,
    #[strum(serialize = "hsts-not-implemented")]
    HstsNotImplemented,
    #[strum(serialize = "hsts-header-invalid")]
    HstsHeaderInvalid,
    #[strum(serialize = "hsts-not-implemented-no-https")]
    HstsNotImplementedNoHttps,
    #[strum(serialize = "hsts-invalid-cert")]
    HstsInvalidCert,

    // SRI
    #[strum(serialize = "sri-implemented-and-all-scripts-loaded-securely")]
    SriImplementedAndAllScriptsLoadedSecurely,
    #[strum(serialize = "sri-implemented-and-external-scripts-loaded-securely")]
    SriImplementedAndExternalScriptsLoadedSecurely,
    #[strum(serialize = "sri-not-implemented-response-not-html")]
    SriNotImplementedResponseNotHtml,
    #[strum(serialize = "sri-not-implemented-but-no-scripts-loaded")]
    SriNotImplementedButNoScriptsLoaded,
    #[strum(serialize = "sri-not-implemented-but-all-scripts-loaded-from-secure-origin")]
    SriNotImplementedButAllScriptsLoadedFromSecureOrigin,
    #[strum(serialize = "sri-not-implemented-but-external-scripts-loaded-securely")]
    SriNotImplementedButExternalScriptsLoadedSecurely,
    #[strum(serialize = "sri-implemented-but-external-scripts-not-loaded-securely")]
    SriImplementedButExternalScriptsNotLoadedSecurely,
    #[strum(serialize = "sri-not-implemented-and-external-scripts-not-loaded-securely")]
    SriNotImplementedAndExternalScriptsNotLoadedSecurely,

    // X-Content-Type-Options
    #[strum(serialize = "x-content-type-options-nosniff")]
    XContentTypeOptionsNosniff,
    #[strum(serialize = "x-content-type-options-not-implemented")]
    XContentTypeOptionsNotImplemented,
    #[strum(serialize = "x-content-type-options-header-invalid")]
    XContentTypeOptionsHeaderInvalid,

    // X-Frame-Options
    #[strum(serialize = "x-frame-options-implemented-via-csp")]
    XFrameOptionsImplementedViaCsp,
    #[strum(serialize = "x-frame-options-sameorigin-or-deny")]
    XFrameOptionsSameoriginOrDeny,
    #[strum(serialize = "x-frame-options-allow-from-origin")]
    XFrameOptionsAllowFromOrigin,
    #[strum(serialize = "x-frame-options-not-implemented")]
    XFrameOptionsNotImplemented,
    #[strum(serialize = "x-frame-options-header-invalid")]
    XFrameOptionsHeaderInvalid,

    // X-XSS-Protection
    #[strum(serialize = "x-xss-protection-enabled-mode-block")]
    XXssProtectionEnabledModeBlock,
    #[strum(serialize = "x-xss-protection-enabled")]
    XXssProtectionEnabled,
    #[strum(serialize = "x-xss-protection-disabled")]
    XXssProtectionDisabled,
    #[strum(serialize = "x-xss-protection-not-implemented")]
    XXssProtectionNotImplemented,
    #[strum(serialize = "x-xss-protection-header-invalid")]
    XXssProtectionHeaderInvalid,

    // Generic
    #[strum(serialize = "html-not-parsable")]
    HtmlNotParsable,
    #[strum(serialize = "request-did-not-return-status-code-200")]
    RequestDidNotReturnStatusCode200,
    #[strum(serialize = "xml-not-parsable")]
    XmlNotParsable,

    // Permissions Policy
    #[strum(serialize = "permissions-policy-implemented")]
    PermissionsPolicyImplemented,
    #[strum(serialize = "permissions-policy-not-implemented")]
    PermissionsPolicyNotImplemented,
    #[strum(serialize = "permissions-policy-header-invalid")]
    PermissionsPolicyHeaderInvalid,

    // Cross-Origin Isolation
    #[strum(serialize = "coop-implemented")]
    CrossOriginOpenerPolicyImplemented,
    #[strum(serialize = "coop-not-implemented")]
    CrossOriginOpenerPolicyNotImplemented,
    #[strum(serialize = "coop-header-invalid")]
    CrossOriginOpenerPolicyHeaderInvalid,

    #[strum(serialize = "coep-implemented")]
    CrossOriginEmbedderPolicyImplemented,
    #[strum(serialize = "coep-not-implemented")]
    CrossOriginEmbedderPolicyNotImplemented,
    #[strum(serialize = "coep-header-invalid")]
    CrossOriginEmbedderPolicyHeaderInvalid,

    #[strum(serialize = "corp-implemented")]
    CrossOriginResourcePolicyImplemented,
    #[strum(serialize = "corp-not-implemented")]
    CrossOriginResourcePolicyNotImplemented,
    #[strum(serialize = "corp-header-invalid")]
    CrossOriginResourcePolicyHeaderInvalid,

    // Security.txt
    #[strum(serialize = "security-txt-implemented")]
    SecurityTxtImplemented,
    #[strum(serialize = "security-txt-not-implemented")]
    SecurityTxtNotImplemented,
}

impl TestResult {
    pub fn modifier(&self) -> i16 {
        match self {
            // CSP
            TestResult::CspImplementedWithNoUnsafeDefaultSrcNone => 10,
            TestResult::CspImplementedWithNoUnsafe => 5,
            TestResult::CspImplementedWithUnsafeInlineInStyleSrcOnly => 0,
            TestResult::CspImplementedWithInsecureSchemeInPassiveContentOnly => -10,
            TestResult::CspImplementedWithUnsafeEval => -10,
            TestResult::CspImplementedWithUnsafeInline => -20,
            TestResult::CspImplementedWithInsecureScheme => -20,
            TestResult::CspHeaderInvalid => -20,
            TestResult::CspNotImplemented => -25,

            // Cookies
            TestResult::CookiesSecureWithHttponlySessionsAndSamesite => 5,
            TestResult::CookiesSecureWithHttponlySessions => 0,
            TestResult::CookiesNotFound => 0,
            TestResult::CookiesWithoutSecureFlagButProtectedByHsts => -5,
            TestResult::CookiesSessionWithoutSecureFlagButProtectedByHsts => -10,
            TestResult::CookiesWithoutSecureFlag => -20,
            TestResult::CookiesSamesiteFlagInvalid => -20,
            TestResult::CookiesAnticsrfWithoutSamesiteFlag => -20,
            TestResult::CookiesSessionWithoutHttponlyFlag => -30,
            TestResult::CookiesSessionWithoutSecureFlag => -40,

            // CORS
            TestResult::CorsNotImplemented => 0,
            TestResult::CorsImplementedWithPublicAccess => 0,
            TestResult::CorsImplementedWithRestrictedAccess => 0,
            TestResult::CorsImplementedWithUniversalAccess => -5,

            // Redirection
            TestResult::RedirectionAllRedirectsPreloaded => 0,
            TestResult::RedirectionToHttps => 0,
            TestResult::RedirectionNotNeededNoHttp => 0,
            TestResult::RedirectionOffHostFromHttp => -5,
            TestResult::RedirectionNotToHttpsOnInitialRedirection => -10,
            TestResult::RedirectionNotToHttps => -20,
            TestResult::RedirectionMissing => -20,
            TestResult::RedirectionInvalidCert => -20,

            // Referrer Policy
            TestResult::ReferrerPolicyPrivate => 5,
            TestResult::ReferrerPolicyNoReferrerWhenDowngrade => 0,
            TestResult::ReferrerPolicyNotImplemented => 0,
            TestResult::ReferrerPolicyUnsafe => -5,
            TestResult::ReferrerPolicyHeaderInvalid => -5,

            // HSTS
            TestResult::HstsPreloaded => 5,
            TestResult::HstsImplementedMaxAgeAtLeastSixMonths => 10,
            TestResult::HstsImplementedMaxAgeLessThanSixMonths => 0,
            TestResult::HstsNotImplemented => -20,
            TestResult::HstsHeaderInvalid => -20,
            TestResult::HstsNotImplementedNoHttps => -20,
            TestResult::HstsInvalidCert => -20,

            // SRI
            TestResult::SriImplementedAndAllScriptsLoadedSecurely => 5,
            TestResult::SriImplementedAndExternalScriptsLoadedSecurely => 5,
            TestResult::SriNotImplementedResponseNotHtml => 0,
            TestResult::SriNotImplementedButNoScriptsLoaded => 0,
            TestResult::SriNotImplementedButAllScriptsLoadedFromSecureOrigin => 0,
            TestResult::SriNotImplementedButExternalScriptsLoadedSecurely => -5,
            TestResult::SriImplementedButExternalScriptsNotLoadedSecurely => -20,
            TestResult::SriNotImplementedAndExternalScriptsNotLoadedSecurely => -20,

            // X-Content-Type-Options
            TestResult::XContentTypeOptionsNosniff => 0,
            TestResult::XContentTypeOptionsNotImplemented => -5,
            TestResult::XContentTypeOptionsHeaderInvalid => -5,

            // X-Frame-Options
            TestResult::XFrameOptionsImplementedViaCsp => 5,
            TestResult::XFrameOptionsSameoriginOrDeny => 0,
            TestResult::XFrameOptionsAllowFromOrigin => 0,
            TestResult::XFrameOptionsNotImplemented => -20,
            TestResult::XFrameOptionsHeaderInvalid => -20,

            // X-XSS-Protection
            TestResult::XXssProtectionEnabledModeBlock => 0,
            TestResult::XXssProtectionEnabled => 0,
            TestResult::XXssProtectionDisabled => 0,
            TestResult::XXssProtectionNotImplemented => 0,
            TestResult::XXssProtectionHeaderInvalid => -5,

            // Permissions Policy
            TestResult::PermissionsPolicyImplemented => 10,
            TestResult::PermissionsPolicyNotImplemented => -20,
            TestResult::PermissionsPolicyHeaderInvalid => -20,

            // Cross-Origin Isolation
            TestResult::CrossOriginOpenerPolicyImplemented => 5,
            TestResult::CrossOriginOpenerPolicyNotImplemented => 0,
            TestResult::CrossOriginOpenerPolicyHeaderInvalid => 0,

            TestResult::CrossOriginEmbedderPolicyImplemented => 5,
            TestResult::CrossOriginEmbedderPolicyNotImplemented => 0,
            TestResult::CrossOriginEmbedderPolicyHeaderInvalid => 0,

            TestResult::CrossOriginResourcePolicyImplemented => 5,
            TestResult::CrossOriginResourcePolicyNotImplemented => 0,
            TestResult::CrossOriginResourcePolicyHeaderInvalid => 0,

            // Security.txt
            TestResult::SecurityTxtImplemented => 5,
            TestResult::SecurityTxtNotImplemented => -5,

            // Generic
            TestResult::HtmlNotParsable => -20,
            TestResult::RequestDidNotReturnStatusCode200 => -5,
            TestResult::XmlNotParsable => -20,
        }
    }

    pub fn description(&self) -> &'static str {
         match self {
            // CSP
            TestResult::CspImplementedWithNoUnsafeDefaultSrcNone => "Content Security Policy (CSP) implemented with default-src 'none' and no 'unsafe'",
            TestResult::CspImplementedWithNoUnsafe => "Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval'",
            TestResult::CspImplementedWithUnsafeInlineInStyleSrcOnly => "Content Security Policy (CSP) implemented with unsafe-inline allowed in style-src only",
            TestResult::CspImplementedWithInsecureSchemeInPassiveContentOnly => "Content Security Policy (CSP) implemented, but allows insecure schemes in passive content",
            TestResult::CspImplementedWithUnsafeEval => "Content Security Policy (CSP) implemented, but allows 'unsafe-eval'",
            TestResult::CspImplementedWithUnsafeInline => "Content Security Policy (CSP) implemented, but allows 'unsafe-inline'",
            TestResult::CspImplementedWithInsecureScheme => "Content Security Policy (CSP) implemented, but allows insecure schemes",
            TestResult::CspHeaderInvalid => "Content Security Policy (CSP) header cannot be parsed",
            TestResult::CspNotImplemented => "Content Security Policy (CSP) header not implemented",

            // Cookies
            TestResult::CookiesSecureWithHttponlySessionsAndSamesite => "All cookies use the Secure flag, session cookies use the HttpOnly flag, and cross-origin restrictions are in place via the SameSite flag",
            TestResult::CookiesSecureWithHttponlySessions => "All cookies use the Secure flag and session cookies use the HttpOnly flag",
            TestResult::CookiesNotFound => "No cookies detected",
            TestResult::CookiesWithoutSecureFlagButProtectedByHsts => "Cookies set without using the Secure flag, but transmission over HTTP prevented by HSTS",
            TestResult::CookiesSessionWithoutSecureFlagButProtectedByHsts => "Session cookie set without using the Secure flag, but transmission over HTTP prevented by HSTS",
            TestResult::CookiesWithoutSecureFlag => "Cookies set without using the Secure flag",
            TestResult::CookiesSamesiteFlagInvalid => "Cookies use an invalid SameSite flag",
            TestResult::CookiesAnticsrfWithoutSamesiteFlag => "Anti-CSRF tokens set without using the SameSite flag",
            TestResult::CookiesSessionWithoutHttponlyFlag => "Session cookie set without the HttpOnly flag",
            TestResult::CookiesSessionWithoutSecureFlag => "Session cookie set without using the Secure flag",

            // CORS
            TestResult::CorsNotImplemented => "Content is not visible via cross-origin resource sharing (CORS) files or headers",
            TestResult::CorsImplementedWithPublicAccess => "Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains",
            TestResult::CorsImplementedWithRestrictedAccess => "Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains",
            TestResult::CorsImplementedWithUniversalAccess => "Content is visible via cross-origin resource sharing (CORS) files or headers from any domain",

            // Redirection
             TestResult::RedirectionAllRedirectsPreloaded => "All redirects are to preloaded HSTS domains",
            TestResult::RedirectionToHttps => "Initial redirection is to HTTPS on this host",
            TestResult::RedirectionNotNeededNoHttp => "Not applicable: plain HTTP not supported",
            TestResult::RedirectionOffHostFromHttp => "Initial redirection from HTTP is to a different host",
            TestResult::RedirectionNotToHttpsOnInitialRedirection => "Initial redirection from HTTP is not to HTTPS",
            TestResult::RedirectionNotToHttps => "Redirects do not eventually land on HTTPS",
            TestResult::RedirectionMissing => "Does not redirect to HTTPS",
            TestResult::RedirectionInvalidCert => "Invalid certificate chain encountered during redirection",

            // Referrer Policy
            TestResult::ReferrerPolicyPrivate => "Referrer-Policy header set to 'no-referrer', 'same-origin', 'strict-origin' or 'strict-origin-when-cross-origin'",
            TestResult::ReferrerPolicyNoReferrerWhenDowngrade => "Referrer-Policy header set to 'no-referrer-when-downgrade'",
            TestResult::ReferrerPolicyNotImplemented => "Referrer-Policy header not implemented",
            TestResult::ReferrerPolicyUnsafe => "Referrer-Policy header set to 'unsafe-url', 'origin', or 'origin-when-cross-origin'",
            TestResult::ReferrerPolicyHeaderInvalid => "Referrer-Policy header cannot be parsed",

            // HSTS
            TestResult::HstsPreloaded => "Preloaded via the HTTP Strict Transport Security (HSTS) preload list",
            TestResult::HstsImplementedMaxAgeAtLeastSixMonths => "HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000)",
            TestResult::HstsImplementedMaxAgeLessThanSixMonths => "HTTP Strict Transport Security (HSTS) header set to less than six months (15768000)",
            TestResult::HstsNotImplemented => "HTTP Strict Transport Security (HSTS) header not implemented",
            TestResult::HstsHeaderInvalid => "HTTP Strict Transport Security (HSTS) header cannot be parsed",
            TestResult::HstsNotImplementedNoHttps => "HTTP Strict Transport Security (HSTS) header not implemented",
            TestResult::HstsInvalidCert => "HTTP Strict Transport Security (HSTS) header cannot be recognized due to an invalid certificate chain",

            // SRI
            TestResult::SriImplementedAndAllScriptsLoadedSecurely => "Subresource Integrity (SRI) implemented and all scripts are loaded from a similar origin",
            TestResult::SriImplementedAndExternalScriptsLoadedSecurely => "Subresource Integrity (SRI) implemented and all scripts are loaded securely",
            TestResult::SriNotImplementedResponseNotHtml => "Subresource Integrity (SRI) is not needed since the response is not HTML",
            TestResult::SriNotImplementedButNoScriptsLoaded => "Subresource Integrity (SRI) is not needed since site contains no script tags",
            TestResult::SriNotImplementedButAllScriptsLoadedFromSecureOrigin => "Subresource Integrity (SRI) not implemented, but all scripts are loaded from a similar origin",
            TestResult::SriNotImplementedButExternalScriptsLoadedSecurely => "Subresource Integrity (SRI) not implemented, but all external scripts are loaded over HTTPS",
            TestResult::SriImplementedButExternalScriptsNotLoadedSecurely => "Subresource Integrity (SRI) implemented, but external scripts are loaded over HTTP or use protocol relative URLs",
            TestResult::SriNotImplementedAndExternalScriptsNotLoadedSecurely => "Subresource Integrity (SRI) not implemented, and external scripts are loaded over HTTP or use protocol relative URLs",

            // X-Content-Type-Options
            TestResult::XContentTypeOptionsNosniff => "X-Content-Type-Options header set to 'nosniff'",
            TestResult::XContentTypeOptionsNotImplemented => "X-Content-Type-Options header not implemented",
            TestResult::XContentTypeOptionsHeaderInvalid => "X-Content-Type-Options header cannot be parsed",

            // X-Frame-Options
            TestResult::XFrameOptionsImplementedViaCsp => "X-Frame-Options (XFO) implemented via the Content Security Policy (CSP) frame-ancestors directive",
            TestResult::XFrameOptionsSameoriginOrDeny => "X-Frame-Options (XFO) header set to SAMEORIGIN or DENY",
            TestResult::XFrameOptionsAllowFromOrigin => "X-Frame-Options (XFO) header set to ALLOW-FROM uri",
            TestResult::XFrameOptionsNotImplemented => "X-Frame-Options (XFO) header not implemented",
            TestResult::XFrameOptionsHeaderInvalid => "X-Frame-Options (XFO) header cannot be parsed",

            // X-XSS-Protection
            TestResult::XXssProtectionEnabledModeBlock => "X-XSS-Protection header set to '1; mode=block'",
            TestResult::XXssProtectionEnabled => "X-XSS-Protection header set to '1'",
            TestResult::XXssProtectionDisabled => "X-XSS-Protection header set to '0' (disabled)",
            TestResult::XXssProtectionNotImplemented => "X-XSS-Protection header not implemented",
            TestResult::XXssProtectionHeaderInvalid => "X-XSS-Protection header cannot be parsed",

            // Generic
            TestResult::HtmlNotParsable => "The HTML could not be parsed",
            TestResult::RequestDidNotReturnStatusCode200 => "The request returned a non-200 status code",
            TestResult::XmlNotParsable => "The XML could not be parsed",

            // Permissions Policy
            TestResult::PermissionsPolicyImplemented => "Permissions-Policy header implemented",
            TestResult::PermissionsPolicyNotImplemented => "Permissions-Policy header not implemented",
            TestResult::PermissionsPolicyHeaderInvalid => "Permissions-Policy header cannot be parsed",

            // Cross-Origin Isolation
            TestResult::CrossOriginOpenerPolicyImplemented => "Cross-Origin-Opener-Policy (COOP) header implemented",
            TestResult::CrossOriginOpenerPolicyNotImplemented => "Cross-Origin-Opener-Policy (COOP) header not implemented",
            TestResult::CrossOriginOpenerPolicyHeaderInvalid => "Cross-Origin-Opener-Policy (COOP) header cannot be parsed",

            TestResult::CrossOriginEmbedderPolicyImplemented => "Cross-Origin-Embedder-Policy (COEP) header implemented",
            TestResult::CrossOriginEmbedderPolicyNotImplemented => "Cross-Origin-Embedder-Policy (COEP) header not implemented",
            TestResult::CrossOriginEmbedderPolicyHeaderInvalid => "Cross-Origin-Embedder-Policy (COEP) header cannot be parsed",

            TestResult::CrossOriginResourcePolicyImplemented => "Cross-Origin-Resource-Policy (CORP) header implemented",
            TestResult::CrossOriginResourcePolicyNotImplemented => "Cross-Origin-Resource-Policy (CORP) header not implemented",
            TestResult::CrossOriginResourcePolicyHeaderInvalid => "Cross-Origin-Resource-Policy (CORP) header cannot be parsed",

            // Security.txt
            TestResult::SecurityTxtImplemented => "security.txt file found and accessible",
            TestResult::SecurityTxtNotImplemented => "security.txt file not found or inaccessible",
        }
    }
}
