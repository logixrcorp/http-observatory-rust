# Logixr Corp HTTP Observatory (CLI)

A high-performance, stateless Command Line Interface for auditing website security headers and TLS configuration, written in Rust.

## Attribution
This project is a port of the [Mozilla HTTP Observatory](https://github.com/mozilla/http-observatory) (MPL 2.0).
Architected by Logixr Corp for internal security auditing.

## Features
- **Security Headers**: Analyzes CSP, HSTS, XFO, SRI, and more.
- **Deep TLS**: Inspects TLS protocol versions (TLS 1.0/1.1 detection).
- **Active Scanning**: Safe canary injection checks for XSS and SQLi.
- **Modern Standards**: Checks for Permissions-Policy, COOP, COEP, CORP.
- **Reporting**: Generates detailed Markdown reports.

## Usage

```bash
# Build the tool
cargo build --release

# Run a scan
cargo run --release -- --url https://example.com --output report.md --active

# Run EXE
# Scans the headers and TLS of a website and outputs them into a Markdown file named Report.md.
httpobs-rust.exe -u https://example.com

# Scans the headers and TLS of a website and outputs them into a Markdown file named Example.md
httpobs-rust.exe -u https://example.com -o Example.md

# Includes Basic check on XSS and SQLi checks (beta)
httpobs-rust.exe -u https://example.com -o Example.md -a
```

## Options
- `-u`, `--url <URL>`: Target URL.
- `-o`, `--output <FILE>`: Output Markdown file (default: `report.md`).
- `-a`, `--active`: Enable active vulnerability scanning (XSS/SQLi checks).

## License
Mozilla Public License 2.0

