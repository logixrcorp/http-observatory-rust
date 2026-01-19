use clap::Parser;
use log::{info, error};
use std::process::exit;
use httpobs_rust::scanner;
use httpobs_rust::reporting;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL to scan
    #[arg(short, long)]
    url: String,

    /// Output report filename
    #[arg(short, long, default_value = "report.md")]
    output: String,

    /// Enable active vulnerability scanning
    #[arg(short, long)]
    active: bool,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    info!("Starting scan for {}", args.url);
    if args.active {
        info!("Active scanning ENABLED");
        println!("WARNING: Active scanning enabled. This will perform real HTTP requests with payloads.");
    }

    let scanner = scanner::engine::Scanner::new(args.active);
    
    // Parse URL
    let target_url = if args.url.starts_with("http") {
        url::Url::parse(&args.url).expect("Invalid URL")
    } else {
        url::Url::parse(&format!("http://{}", args.url)).expect("Invalid URL")
    };
    
    let domain = target_url.host_str().unwrap_or(args.url.as_str()).to_string();

    match scanner.scan_site(&target_url).await {
        Ok(results) => {
            info!("Scan complete. Generating report...");
            reporting::generate_report(&results, &args.output, &domain);
            info!("Report saved to {}", args.output);
        }
        Err(e) => {
            error!("Scan failed: {}", e);
            exit(1);
        }
    }
}
