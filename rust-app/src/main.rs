mod api;
mod db;
mod scanner;
mod utils;

use dotenvy::dotenv;
use std::{env, sync::Arc};
use axum::{
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use crate::db::repo::Repository;
use crate::scanner::engine::Scanner;
use crate::api::handlers::{analyze, get_results, get_scan_results, get_host_history, get_recent_scans, get_grade_distribution, heartbeat, lbheartbeat, version, AppState};
use clap::{Parser, Subcommand};
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use axum::http::{HeaderName, HeaderValue};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the API server (default)
    Serve,
    /// Scan a specific hostname and output JSON
    Scan {
        /// Hostname to scan
        domain: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    env_logger::init();
    
    let cli = Cli::parse();
    
    // Core Initialization
    let scanner = Arc::new(Scanner::new()); 

    match &cli.command {
        Some(Commands::Scan { domain }) => {
            // CLI Mode
            use crate::scanner::grade::Grader;
            use serde::Serialize;
            use serde_json::json;

            let results = scanner.scan_site(domain).await?;
            let (score, grade) = Grader::grade(&results);

            #[derive(Serialize)]
            struct DetailedResult {
                name: String,
                score_modifier: i16,
                description: String,
            }

            let detailed_results: Vec<DetailedResult> = results.iter().map(|r| DetailedResult {
                name: format!("{:?}", r),
                score_modifier: r.modifier(),
                description: r.description().to_string(), 
            }).collect();

            let report = json!({
                "domain": domain,
                "score": score,
                "grade": grade,
                "results": detailed_results
            });

            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some(Commands::Serve) | None => {
            // Server Mode
            println!("Starting Http Observatory Rust...");
            
            // Database Connection
            let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://httpobsapi:httpobsapi@localhost/httpobs".to_string());
            
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect_lazy(&database_url)
                .unwrap_or_else(|e| {
                    println!("Warning: Invalid database URL or connection error: {}. Running in unstable mode.", e);
                    // We still need a pool to proceed, but if connecting lazily fails, it's usually a URL parse error.
                    // We can't easily return a "fake" pool.
                    // If lazy connect fails, we MUST panic or exit, but lazy connect rarely fails unless config is malformed.
                    panic!("Failed to create database pool: {}", e);
                });
        
            let repo = Repository::new(pool.clone());
            
            // Background Maintenance Task
            let maintenance_pool = pool.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if let Err(e) = sqlx::query("UPDATE scans SET state = 'ABORTED' WHERE state = 'RUNNING' AND start_time < NOW() - INTERVAL '5 minutes'")
                        .execute(&maintenance_pool)
                        .await 
                    {
                        log::error!("Database maintenance failed: {}", e);
                    }
                }
            });
        
            let app_state = AppState {
                repo,
                scanner,
            };

            // Middleware Configuration
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);

            let app = Router::new()
                .route("/api/v1/analyze", post(analyze).get(get_results))
                .route("/api/v1/getScanResults", get(get_scan_results))
                .route("/api/v1/getHostHistory", get(get_host_history))
                .route("/api/v1/getRecentScans", get(get_recent_scans))
                .route("/api/v1/getGradeDistribution", get(get_grade_distribution))
                .route("/__heartbeat__", get(heartbeat))
                .route("/__lbheartbeat__", get(lbheartbeat))
                .route("/__version__", get(version))
                .with_state(app_state)
                .layer(cors)
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_static("default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("referrer-policy"),
                    HeaderValue::from_static("no-referrer"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("strict-transport-security"),
                    HeaderValue::from_static("max-age=63072000"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-content-type-options"),
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-xss-protection"),
                    HeaderValue::from_static("1; mode=block"),
                ));
        
            let addr = "0.0.0.0:3000";
            println!("Listening on {}", addr);
            
            axum::Server::bind(&addr.parse().unwrap())
                .serve(app.into_make_service())
                .await
                .unwrap();
            
            Ok(())
        }
    }
}
