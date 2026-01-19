# Build Stage
FROM rust:1.76-slim-bookworm as builder

WORKDIR /usr/src/app
COPY . .

# Build release binary
RUN cargo build --release

# Runtime Stage
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /usr/src/app/target/release/httpobs-rust /usr/local/bin/httpobs-rust

ENV RUST_LOG=info
WORKDIR /usr/local/bin

CMD ["./httpobs-rust"]
