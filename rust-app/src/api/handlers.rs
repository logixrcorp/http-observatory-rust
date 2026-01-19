use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use crate::db::repo::Repository;
use crate::scanner::engine::Scanner;
use std::sync::Arc;
use chrono::Utc;

#[derive(Clone)]
pub struct AppState {
    pub repo: Repository,
    pub scanner: Arc<Scanner>,
}

#[derive(Deserialize)]
pub struct AnalyzeParams {
    pub host: String,
    pub rescan: Option<bool>,
}

#[derive(Serialize)]
pub struct ScanResponse {
    pub message: String,
    pub domain: String,
    pub scan_id: Option<i32>,
}

#[derive(Deserialize)]
pub struct ScanResultParams {
    pub scan: i32,
}

#[derive(Deserialize)]
pub struct RecentScansParams {
    pub num: Option<i64>,
}

pub async fn analyze(
    State(state): State<AppState>,
    Query(params): Query<AnalyzeParams>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let domain = params.host.to_lowercase();
    let rescan = params.rescan.unwrap_or(false);

    // 0. Input Validation
    if !crate::utils::is_valid_hostname(&domain) {
        return Err((StatusCode::BAD_REQUEST, "Invalid hostname".to_string()));
    }

    // 1. Get or Create Site
    let site = match state.repo.get_site_by_domain(&domain).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))? {
        Some(s) => s,
        None => state.repo.create_site(&domain).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    };

    // 2. Check Cooldown (if not forcing rescan)
    if !rescan {
        if let Ok(Some(latest_scan)) = state.repo.get_latest_scan(site.id).await {
            let cooldown_seconds = 60; // 1 minute cooldown
            let now = Utc::now().naive_utc();
            // Assuming start_time is NaiveDateTime (UTC-ish)
            let duration = now.signed_duration_since(latest_scan.start_time);
            
            if duration.num_seconds() < cooldown_seconds && latest_scan.state == crate::db::models::ScanState::Finished {
                 return Ok(Json(ScanResponse {
                    message: "Cached result returned (cooldown active). Use rescan=true to force.".to_string(),
                    domain,
                    scan_id: Some(latest_scan.id),
                }));
            }
        }
    }

    // 3. Trigger Scan
    let scan_result = state.scanner.scan_site(&domain).await;

    let (results, error) = match scan_result {
        Ok(res) => (res, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };

    // 4. Calculate Grade
    let (score, grade) = crate::scanner::grade::Grader::grade(&results);

    // 5. Save Results
    let scan_id = state.repo.save_scan(site.id, &results, score, grade, error).await
         .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 6. Return Success
    Ok(Json(ScanResponse {
        message: "Scan completed and saved.".to_string(),
        domain,
        scan_id: Some(scan_id),
    }))
}

pub async fn get_results(
    State(state): State<AppState>,
    Query(params): Query<AnalyzeParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let domain = params.host.to_lowercase();
    
    let site = state.repo.get_site_by_domain(&domain).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(site) = site {
        let scan = state.repo.get_latest_scan(site.id).await
             .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        if let Some(scan) = scan {
            Ok(Json(serde_json::to_value(scan).unwrap()))
        } else {
             Err((StatusCode::NOT_FOUND, "No scan found for this site".to_string()))
        }
    } else {
        Err((StatusCode::NOT_FOUND, "Site not found".to_string()))
    }
}

pub async fn get_scan_results(
    State(state): State<AppState>,
    Query(params): Query<ScanResultParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tests = state.repo.get_test_results(params.scan).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::to_value(tests).unwrap()))
}

pub async fn get_host_history(
    State(state): State<AppState>,
    Query(params): Query<AnalyzeParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let domain = params.host.to_lowercase();
    
    let site = state.repo.get_site_by_domain(&domain).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(site) = site {
        let history = state.repo.get_host_history(site.id).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(Json(serde_json::to_value(history).unwrap()))
    } else {
        Err((StatusCode::NOT_FOUND, "Site not found".to_string()))
    }
}

pub async fn get_recent_scans(
    State(state): State<AppState>,
    Query(params): Query<RecentScansParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let num = params.num.unwrap_or(10).clamp(1, 25);
    let scans = state.repo.get_recent_scans(num).await
         .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::to_value(scans).unwrap()))
}

pub async fn get_grade_distribution(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let distribution = state.repo.get_grade_distribution().await
         .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Transform to map { "A": 10, "B": 5 }
    let mut map = serde_json::Map::new();
    for entry in distribution {
        map.insert(entry.grade, serde_json::Value::Number(serde_json::Number::from(entry.count)));
    }

    Ok(Json(serde_json::Value::Object(map)))
}

// Monitoring Handlers
pub async fn heartbeat(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Check DB
    if state.repo.ping().await.is_ok() {
        Json(serde_json::json!({"database": "OK"}))
    } else {
        Json(serde_json::json!({"database": "FAIL"}))
    }
}

pub async fn lbheartbeat() -> StatusCode {
    StatusCode::OK
}

pub async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "source": "https://github.com/mozilla/http-observatory",
        "version": "Rust-0.1.0"
    }))
}
