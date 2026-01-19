# Mozilla HTTP Observatory (Rust)

The Mozilla HTTP Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it.

> [!NOTE]
> This is a modern port of the original HTTP Observatory to **Rust**. It replaces the legacy Python implementation with a high-performance, type-safe alternative while maintaining feature parity.

It is split into three projects:

* [http-observatory](https://github.com/mozilla/http-observatory) - scanner/grader (This Repository)
* [observatory-cli](https://github.com/mozilla/observatory-cli) - command line interface
* [http-observatory-website](https://github.com/mozilla/http-observatory-website) - web interface

## Key Features

In addition to standard HTTP security header analysis, this Rust port introduces **Advanced "Vibe Coding" Detection** to identify risks common in modern, AI-assisted development:

*   **🛡️ Core Security Headers**: CSP, HSTS, SRI, X-Content-Type-Options, etc.
*   **🤖 AI "Slop" Detection**: Identifies unreviewed AI-generated code artifacts and placeholders. (beta)
*   **🔑 Secrets Scanner**: Detects hardcoded API keys (OpenAI, AWS, etc.) and credentials in client code.
*   **🔌 Direct DB & Backend Leaks**: Flags client-side database connections (`postgres://`) and server imports (`require('mongoose')`).  (beta)
*   **⚡ Supabase Audit**: Actively checks for exposed Supabase credentials and disabled Row-Level Security (RLS).  (beta)
*   **☁️ Cloudflare & Edge**: Detects WAF/Edge protection presence.
*   **🚧 Broken Components**: Finds broken links (localhost) and unrendered template syntax.

## Scanning sites with the HTTP Observatory

Sites can be scanned using:

* [observatory.mozilla.org](https://observatory.mozilla.org/) - the online interface
* [observatory-cli](https://github.com/mozilla/observatory-cli) - the official node.js command line interface

## Development

### Prerequisites

* Rust (latest stable)
* Git

### Building the Project

```bash
# Clone the code
$ git clone https://github.com/mozilla/http-observatory.git
$ cd http-observatory/rust-app

# Build release binary
$ cargo build --release
```

### Running tests

```bash
$ cargo test
```

## Running a scan from the local codebase (CLI)

The Rust application includes a built-in CLI for scanning sites directly without a database or server infrastructure, ideal for CI/CD.

```bash
# Run a scan against a target
$ cargo run --release --bin httpobs-rust -- --http-port 80 --https-port 443 mozilla.org
```

### Options

```bash
$ cargo run --release -- --help
```

* `--http-port <PORT>`: Set the HTTP port (default: 80)
* `--https-port <PORT>`: Set the HTTPS port (default: 443)
* `--path <PATH>`: Scan a specific path (default: /)
* `--json`: Output results as JSON

## Docker

Build and run the containerized scanner:

```bash
$ docker build -t httpobs-rust .
$ docker run -it httpobs-rust

$ docker run -it httpobs-rust httpobs-rust scan google.com
```

## Authors

* April King (Original Python Implementation)
* Ehren Schlueter (Rust Port Implementation)

## License

* Mozilla Public License Version 2.0

