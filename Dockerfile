# syntax=docker/dockerfile:1
FROM rust:1.83-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates python3 tini && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/keyhunter-rs /usr/local/bin/keyhunter-rs
COPY settings.json /app/settings.json
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app/data
ENV DB_PATH=/app/data/scanner.db \
    PROXY_OWNED=/app/data/owned_proxies.txt \
    PROXY_CACHE=/app/data/proxies.json \
    NO_POLL=1 \
    NOTIFY_START=0 \
    RUST_LOG=info \
    PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/entrypoint.sh"]