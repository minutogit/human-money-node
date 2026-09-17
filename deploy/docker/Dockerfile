# ==============================================================================
# Human Money Node (humoco-node) - Multi-Stage Dockerfile
# ==============================================================================

# Stage 1: Builder
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/humoco

# Copy workspace manifests and source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Compile production release binary for humoco-node
RUN cargo build --release -p humoco-node

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group (uid/gid 10001)
RUN groupadd -g 10001 humoco && \
    useradd -u 10001 -g humoco -m -s /bin/bash humoco && \
    mkdir -p /data /config && \
    chown -R humoco:humoco /data /config

# Copy compiled binary from builder
COPY --from=builder /usr/src/humoco/target/release/humoco-node /usr/local/bin/humoco
RUN ln -s /usr/local/bin/humoco /usr/local/bin/humoco-node

# Expose QUIC P2P (UDP) and Client Ingress (TCP)
EXPOSE 9090/udp
EXPOSE 8080/tcp

# Declare mount points for database state and configuration
VOLUME ["/data", "/config"]

# Run unprivileged
USER humoco:humoco

# Container entrypoint and default daemon run command
ENTRYPOINT ["humoco"]
CMD ["run", "--config", "/config/humoco.toml"]
