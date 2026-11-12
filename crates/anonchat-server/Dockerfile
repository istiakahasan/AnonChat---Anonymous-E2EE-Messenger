# Dockerfile for AnonChat Blind Relay Server
FROM rust:1.80-bullseye AS builder

WORKDIR /usr/src/anonchat

# Copy workspace configuration and dependencies
COPY Cargo.toml ./
COPY crates/anonchat-crypto/ ./crates/anonchat-crypto/
COPY crates/anonchat-server/ ./crates/anonchat-server/
COPY crates/anonchat-client/ ./crates/anonchat-client/
COPY crates/anonchat-ui/ ./crates/anonchat-ui/

# Build optimized release binary
WORKDIR /usr/src/anonchat
RUN cargo build --package anonchat-server --release --bin anonchat-server

# Final minimal runtime image
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-privileged user for security
RUN useradd -m -u 10001 -s /bin/sh anonchat
USER anonchat

WORKDIR /home/anonchat
COPY --from=builder /usr/src/anonchat/target/release/anonchat-server /usr/local/bin/anonchat-server

# Blind relay configuration
ENV PORT=8080
ENV RUST_LOG=anonchat_server=info
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/anonchat-server"]

