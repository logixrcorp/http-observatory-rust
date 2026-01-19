# Build Stage
FROM rust:1.88 AS builder
WORKDIR /app

# Copy the entire project
COPY . .

# Build the Rust application
WORKDIR /app/rust-app
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim
WORKDIR /app

# Install necessary runtime dependencies (SSL certificates)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the build artifact
COPY --from=builder /app/rust-app/target/release/httpobs-rust /usr/local/bin/httpobs-rust

# Copy configuration files
COPY --from=builder /app/conf /app/conf

# Set environment variables if needed
ENV RUST_LOG=info

# Run the application
CMD ["httpobs-rust"]
