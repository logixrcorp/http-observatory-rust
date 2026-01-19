use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, EnumIter};
use sqlx::{Postgres, Type, Decode, Encode};
use sqlx::postgres::{PgTypeInfo, PgValueRef, PgArgumentBuffer};
use std::error::Error;
use std::str::FromStr;

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

impl Type<Postgres> for Grade {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
}

impl<'r> Decode<'r, Postgres> for Grade {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let s = <String as Decode<Postgres>>::decode(value)?;
        Grade::from_str(&s).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)
    }
}

impl<'q> Encode<'q, Postgres> for Grade {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        <String as Encode<Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
}

impl Grade {
    pub fn from_score(score: i16) -> Self {
        let score = score.max(0);
        let score = if score > 100 { 100 } else { score - (score % 5) };
        match score {
            100 => Grade::APlus,
            95 | 90 => Grade::A,
            85 => Grade::AMinus,
            80 => Grade::BPlus,
            75 | 70 => Grade::B,
            65 => Grade::BMinus,
            60 => Grade::CPlus,
            55 | 50 => Grade::C,
            45 => Grade::CMinus,
            40 => Grade::DPlus,
            35 | 30 => Grade::D,
            25 => Grade::DMinus,
            _ => Grade::F,
        }
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

    // Vibe Coding / AI Slop
    #[strum(serialize = "vibe-coding-ai-artifacts-detected")]
    VibeCodingAiArtifactsDetected,
    #[strum(serialize = "vibe-coding-exposed-config")]
    VibeCodingExposedConfig,
    #[strum(serialize = "vibe-coding-source-map-file-detected")]
    VibeCodingSourceMapFileDetected,
    #[strum(serialize = "vibe-coding-source-map-reference-detected")]
    VibeCodingSourceMapReferenceDetected,
    #[strum(serialize = "vibe-coding-clean")]
    VibeCodingClean,
    #[strum(serialize = "vibe-coding-direct-database-connection")]
    VibeCodingDirectDatabaseConnection,
    #[strum(serialize = "vibe-coding-sql-logic-detected")]
    VibeCodingSqlLogicDetected,
    #[strum(serialize = "vibe-coding-server-side-import-detected")]
    VibeCodingServerSideImportDetected,

    // Supabase
    #[strum(serialize = "supabase-credentials-exposed")]
    SupabaseCredentialsExposed,
    #[strum(serialize = "supabase-direct-client-query-detected")]
    SupabaseDirectClientQueryDetected,
    #[strum(serialize = "supabase-rls-not-enforced")]
    SupabaseRlsNotEnforced,
    #[strum(serialize = "supabase-rls-enforced")]
    SupabaseRlsEnforced,

    // Cloudflare
    #[strum(serialize = "cloudflare-proxy-detected")]
    CloudflareProxyDetected,
    #[strum(serialize = "cloudflare-cache-hit")]
    CloudflareCacheHit,
    #[strum(serialize = "cloudflare-cache-miss")]
    CloudflareCacheMiss,
    #[strum(serialize = "cloudflare-not-detected")]
    CloudflareNotDetected,


    // Broken Components
    #[strum(serialize = "broken-component-localhost-link")]
    BrokenComponentLocalhostLink,
    #[strum(serialize = "broken-component-empty-link")]
    BrokenComponentEmptyLink,
    #[strum(serialize = "broken-component-template-leak")]
    BrokenComponentTemplateLeak,
    #[strum(serialize = "broken-component-lorem-ipsum")]
    BrokenComponentLoremIpsum,

    // Secrets Detected
    #[strum(serialize = "secrets-detected-ai-key")]
    SecretsDetectedAiKey,
    #[strum(serialize = "secrets-detected-cloud-key")]
    SecretsDetectedCloudKey,
    #[strum(serialize = "secrets-detected-generic-key")]
    SecretsDetectedGenericKey,
    #[strum(serialize = "secrets-detected-hardcoded-password")]
    SecretsDetectedHardcodedPassword,
}

impl Type<Postgres> for TestResult {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
}

impl<'r> Decode<'r, Postgres> for TestResult {
    fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let s = <String as Decode<Postgres>>::decode(value)?;
        TestResult::from_str(&s).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)
    }
}

impl<'q> Encode<'q, Postgres> for TestResult {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        <String as Encode<Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
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
            // Security.txt
            TestResult::SecurityTxtImplemented => 5,
            TestResult::SecurityTxtNotImplemented => 0,

            // Vibe Coding
            TestResult::VibeCodingAiArtifactsDetected => -20,
            TestResult::VibeCodingExposedConfig => -50,
            TestResult::VibeCodingSourceMapFileDetected => -10,
            TestResult::VibeCodingSourceMapReferenceDetected => -10,
            TestResult::VibeCodingClean => 0,
            TestResult::VibeCodingDirectDatabaseConnection => -50,
            TestResult::VibeCodingSqlLogicDetected => -20,
            TestResult::VibeCodingServerSideImportDetected => -20,

            // Supabase
            TestResult::SupabaseCredentialsExposed => -50,
            TestResult::SupabaseDirectClientQueryDetected => -20,
            TestResult::SupabaseRlsNotEnforced => -50,
            TestResult::SupabaseRlsEnforced => 5,

            // Cloudflare
            TestResult::CloudflareProxyDetected => 10,
            TestResult::CloudflareCacheHit => 5,
            TestResult::CloudflareCacheMiss => 0,
            TestResult::CloudflareNotDetected => 0,

            // Broken Components
            TestResult::BrokenComponentLocalhostLink => -20,
            TestResult::BrokenComponentEmptyLink => -10,
            TestResult::BrokenComponentTemplateLeak => -20,
            TestResult::BrokenComponentLoremIpsum => -5,

            // Secrets
            TestResult::SecretsDetectedAiKey => -50,
            TestResult::SecretsDetectedCloudKey => -50,
            TestResult::SecretsDetectedGenericKey => -20,
            TestResult::SecretsDetectedHardcodedPassword => -50,
            
            // Generic 
            TestResult::HtmlNotParsable => -20,
            TestResult::RequestDidNotReturnStatusCode200 => -5,
            TestResult::XmlNotParsable => -20,
        }
    }



    pub fn description(&self) -> &'static str {
        match self {
            TestResult::CspImplementedWithNoUnsafeDefaultSrcNone => "Content Security Policy (CSP) implemented with default-src 'none' and no 'unsafe'",
            TestResult::CspImplementedWithNoUnsafe => "Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval'",
            TestResult::CspImplementedWithUnsafeInlineInStyleSrcOnly => "Content Security Policy (CSP) implemented with unsafe-inline inside style-src",
            TestResult::CspImplementedWithInsecureSchemeInPassiveContentOnly => "Content Security Policy (CSP) implemented, but allows for insecure passive content (images/media)",
            TestResult::CspImplementedWithUnsafeEval => "Content Security Policy (CSP) implemented, but allows 'unsafe-eval'",
            TestResult::CspImplementedWithUnsafeInline => "Content Security Policy (CSP) implemented, but allows 'unsafe-inline'",
            TestResult::CspImplementedWithInsecureScheme => "Content Security Policy (CSP) implemented, but allows for insecure content",
            TestResult::CspHeaderInvalid => "Content Security Policy (CSP) header cannot be parsed",
            TestResult::CspNotImplemented => "Content Security Policy (CSP) header not implemented",

            TestResult::CookiesSecureWithHttponlySessionsAndSamesite => "All cookies use the Secure flag, session cookies use the HttpOnly flag, and cross-origin restrictions are in place via the SameSite flag",
            TestResult::CookiesSecureWithHttponlySessions => "All cookies use the Secure flag and session cookies use the HttpOnly flag",
            TestResult::CookiesNotFound => "No cookies detected",
            TestResult::CookiesWithoutSecureFlagButProtectedByHsts => "Cookies set without using the Secure flag, but transmission over HTTP prevented by HSTS",
            TestResult::CookiesSessionWithoutSecureFlagButProtectedByHsts => "Session cookie set without using the Secure flag, but transmission over HTTP prevented by HSTS",
            TestResult::CookiesWithoutSecureFlag => "Cookies set without using the Secure flag",
            TestResult::CookiesSamesiteFlagInvalid => "Cookies set with invalid SameSite flag",
            TestResult::CookiesAnticsrfWithoutSamesiteFlag => "Anti-CSRF tokens set without using the SameSite flag",
            TestResult::CookiesSessionWithoutHttponlyFlag => "Session cookie set without using the HttpOnly flag",
            TestResult::CookiesSessionWithoutSecureFlag => "Session cookie set without using the Secure flag",

            TestResult::CorsNotImplemented => "Cross-Origin Resource Sharing (CORS) is not implemented",
            TestResult::CorsImplementedWithPublicAccess => "Cross-Origin Resource Sharing (CORS) implemented with public access",
            TestResult::CorsImplementedWithRestrictedAccess => "Cross-Origin Resource Sharing (CORS) implemented with restricted access",
            TestResult::CorsImplementedWithUniversalAccess => "Cross-Origin Resource Sharing (CORS) implemented with universal access",

            TestResult::RedirectionAllRedirectsPreloaded => "All redirects are to preloaded HTTPS",
            TestResult::RedirectionToHttps => "Redirects to HTTPS",
            TestResult::RedirectionNotNeededNoHttp => "Redirection not needed (no HTTP)",
            TestResult::RedirectionOffHostFromHttp => "Redirects off-host from HTTP",
            TestResult::RedirectionNotToHttpsOnInitialRedirection => "Initial redirection is not to HTTPS",
            TestResult::RedirectionNotToHttps => "Redirects are not to HTTPS",
            TestResult::RedirectionMissing => "Does not redirect to HTTPS",
            TestResult::RedirectionInvalidCert => "Invalid certificate during redirection",

            TestResult::ReferrerPolicyPrivate => "Referrer-Policy header set to strict-origin-when-cross-origin or stricter",
            TestResult::ReferrerPolicyNoReferrerWhenDowngrade => "Referrer-Policy header set to no-referrer-when-downgrade",
            TestResult::ReferrerPolicyNotImplemented => "Referrer-Policy header not implemented",
            TestResult::ReferrerPolicyUnsafe => "Referrer-Policy header set to unsafe values",
            TestResult::ReferrerPolicyHeaderInvalid => "Referrer-Policy header cannot be parsed",

            TestResult::HstsPreloaded => "Preloaded via HSTS",
            TestResult::HstsImplementedMaxAgeAtLeastSixMonths => "HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000)",
            TestResult::HstsImplementedMaxAgeLessThanSixMonths => "HTTP Strict Transport Security (HSTS) header set to less than six months (15768000)",
            TestResult::HstsNotImplemented => "HTTP Strict Transport Security (HSTS) header not implemented",
            TestResult::HstsHeaderInvalid => "HTTP Strict Transport Security (HSTS) header cannot be parsed",
            TestResult::HstsNotImplementedNoHttps => "HTTP Strict Transport Security (HSTS) header cannot be set for sites not served over HTTPS",
            TestResult::HstsInvalidCert => "HTTP Strict Transport Security (HSTS) header cannot be recognized on sites with invalid certificates",

            TestResult::SriImplementedAndAllScriptsLoadedSecurely => "Subresource Integrity (SRI) is implemented and all scripts are loaded securely",
            TestResult::SriImplementedAndExternalScriptsLoadedSecurely => "Subresource Integrity (SRI) is implemented and external scripts are loaded securely",
            TestResult::SriNotImplementedResponseNotHtml => "Subresource Integrity (SRI) is not needed since response is not HTML",
            TestResult::SriNotImplementedButNoScriptsLoaded => "Subresource Integrity (SRI) is not implemented, but no scripts are loaded",
            TestResult::SriNotImplementedButAllScriptsLoadedFromSecureOrigin => "Subresource Integrity (SRI) is not implemented, but all scripts are loaded from a similar origin",
            TestResult::SriNotImplementedButExternalScriptsLoadedSecurely => "Subresource Integrity (SRI) is not implemented, but external scripts are loaded securely",
            TestResult::SriImplementedButExternalScriptsNotLoadedSecurely => "Subresource Integrity (SRI) is implemented, but external scripts are not loaded securely",
            TestResult::SriNotImplementedAndExternalScriptsNotLoadedSecurely => "Subresource Integrity (SRI) is not implemented and external scripts are not loaded securely",

            TestResult::XContentTypeOptionsNosniff => "X-Content-Type-Options header set to 'nosniff'",
            TestResult::XContentTypeOptionsNotImplemented => "X-Content-Type-Options header not implemented",
            TestResult::XContentTypeOptionsHeaderInvalid => "X-Content-Type-Options header cannot be parsed",

            TestResult::XFrameOptionsImplementedViaCsp => "X-Frame-Options (XFO) implemented via the CSP frame-ancestors directive",
            TestResult::XFrameOptionsSameoriginOrDeny => "X-Frame-Options (XFO) header set to SAMEORIGIN or DENY",
            TestResult::XFrameOptionsAllowFromOrigin => "X-Frame-Options (XFO) header set to ALLOW-FROM uri",
            TestResult::XFrameOptionsNotImplemented => "X-Frame-Options (XFO) header not implemented",
            TestResult::XFrameOptionsHeaderInvalid => "X-Frame-Options (XFO) header cannot be parsed",

            TestResult::XXssProtectionEnabledModeBlock => "X-XSS-Protection header set to '1; mode=block'",
            TestResult::XXssProtectionEnabled => "X-XSS-Protection header set to '1'",
            TestResult::XXssProtectionDisabled => "X-XSS-Protection header set to '0' (disabled)",
            TestResult::XXssProtectionNotImplemented => "X-XSS-Protection header not implemented",
            TestResult::XXssProtectionHeaderInvalid => "X-XSS-Protection header cannot be parsed",

            TestResult::PermissionsPolicyImplemented => "Permissions-Policy header implemented",
            TestResult::PermissionsPolicyNotImplemented => "Permissions-Policy header not implemented",
            TestResult::PermissionsPolicyHeaderInvalid => "Permissions-Policy header cannot be parsed",

            TestResult::CrossOriginOpenerPolicyImplemented => "Cross-Origin-Opener-Policy (COOP) header implemented",
            TestResult::CrossOriginOpenerPolicyNotImplemented => "Cross-Origin-Opener-Policy (COOP) header not implemented",
            TestResult::CrossOriginOpenerPolicyHeaderInvalid => "Cross-Origin-Opener-Policy (COOP) header cannot be parsed",

            TestResult::CrossOriginEmbedderPolicyImplemented => "Cross-Origin-Embedder-Policy (COEP) header implemented",
            TestResult::CrossOriginEmbedderPolicyNotImplemented => "Cross-Origin-Embedder-Policy (COEP) header not implemented",
            TestResult::CrossOriginEmbedderPolicyHeaderInvalid => "Cross-Origin-Embedder-Policy (COEP) header cannot be parsed",

            TestResult::CrossOriginResourcePolicyImplemented => "Cross-Origin-Resource-Policy (CORP) header implemented",
            TestResult::CrossOriginResourcePolicyNotImplemented => "Cross-Origin-Resource-Policy (CORP) header not implemented",
            TestResult::CrossOriginResourcePolicyHeaderInvalid => "Cross-Origin-Resource-Policy (CORP) header cannot be parsed",

            TestResult::SecurityTxtImplemented => "security.txt file found and accessible",
            TestResult::SecurityTxtNotImplemented => "security.txt file not found or inaccessible",

            TestResult::VibeCodingAiArtifactsDetected => "Signs of unreviewed AI-generated code detected (AI Slop)",
            TestResult::VibeCodingExposedConfig => "Critical configuration files exposed (e.g. .env, .git)",
            TestResult::VibeCodingSourceMapFileDetected => "Publicly accessible source map file found (e.g. main.js.map)",
            TestResult::VibeCodingSourceMapReferenceDetected => "Source map reference detected in HTML (sourceMappingURL)",
            TestResult::VibeCodingClean => "No vibe coding artifacts detected",
            TestResult::VibeCodingDirectDatabaseConnection => "Critical: Direct database connection string detected in client code (e.g. postgres://)",
            TestResult::VibeCodingSqlLogicDetected => "Backend SQL logic detected in client-side code",
            TestResult::VibeCodingServerSideImportDetected => "Server-side library imports detected in client-side code (e.g. 'require(pg)')",

            TestResult::SupabaseCredentialsExposed => "Critical: Supabase credentials (URL/Anon Key) exposed in client code",
            TestResult::SupabaseDirectClientQueryDetected => "Supabase client-side database queries detected in frontend bundle",
            TestResult::SupabaseRlsNotEnforced => "Critical: Row Level Security (RLS) appears disabled; data is publicly readable via exposed credentials",
            TestResult::SupabaseRlsEnforced => "Supabase RLS appears to be enforcing access controls",

            TestResult::CloudflareProxyDetected => "Traffic is protected by Cloudflare Proxy (DDoS/WAF protection)",
            TestResult::CloudflareCacheHit => "Resource served from Cloudflare Edge Cache (Performance optimized)",
            TestResult::CloudflareCacheMiss => "Resource served from origin via Cloudflare (Cache Miss)",
            TestResult::CloudflareNotDetected => "No Cloudflare protection detected",

            TestResult::BrokenComponentLocalhostLink => "Link to localhost/127.0.0.1 detected in production",
            TestResult::BrokenComponentEmptyLink => "Empty or placeholder link detected (href='#' or '')",
            TestResult::BrokenComponentTemplateLeak => "Unrendered template syntax detected (e.g. {{ var }})",
            TestResult::BrokenComponentLoremIpsum => "Placeholder text 'Lorem Ipsum' detected",

            TestResult::SecretsDetectedAiKey => "Critical: Hardcoded AI API key detected (OpenAI, Anthropic, HuggingFace)",
            TestResult::SecretsDetectedCloudKey => "Critical: Hardcoded Cloud Provider key detected (AWS, Google, Azure)",
            TestResult::SecretsDetectedGenericKey => "Suspicious API key or Authorization token pattern detected",
            TestResult::SecretsDetectedHardcodedPassword => "Hardcoded password assignment detected",

            TestResult::HtmlNotParsable => "Content is not valid HTML/XML",
            TestResult::RequestDidNotReturnStatusCode200 => "Request did not return status code 200",
            TestResult::XmlNotParsable => "Content is not valid XML",
        }
    }
}
pub struct Grader;

impl Grader {
    pub fn grade(results: &[TestResult]) -> (i16, Grade) {
        let mut score: i16 = 100;
        for r in results {
            score += r.modifier();
        }
        let score = score.clamp(0, 100);
        let grade = Grade::from_score(score);
        (score, grade)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grader_perfect_score() {
        let results = vec![];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 100);
        assert_eq!(grade, Grade::APlus);
    }

    #[test]
    fn test_grader_flawed_score() {
        let results = vec![
            TestResult::CspNotImplemented,
            TestResult::HstsNotImplemented,
        ];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 55);
        // 100 - 25 - 20 = 55
        // 55 | 50 => C
        assert_eq!(grade, Grade::C);
    }

    #[test]
    fn test_grader_clamping() {
        let results = vec![
             TestResult::CspNotImplemented, // -25
             TestResult::HstsNotImplemented, // -20
             TestResult::RedirectionMissing, // -20
             TestResult::CookiesSessionWithoutSecureFlag, // -40
             TestResult::ReferrerPolicyHeaderInvalid, // -5
             TestResult::XFrameOptionsNotImplemented // -20
             // Total: -130 => -30
        ];
        let (score, grade) = Grader::grade(&results);
        assert_eq!(score, 0);
        assert_eq!(grade, Grade::F);
    }
}

