# deploy/Dockerfile
# Multi-stage: build the Rust gateway, run non-root on a distroless-ish base.
# No secrets baked in; certs mount at runtime.

FROM rust:1.79-bookworm AS build
WORKDIR /src
# Cache deps first.
COPY gateway/Cargo.toml gateway/Cargo.lock ./gateway/
RUN mkdir -p gateway/src && echo 'fn main(){}' > gateway/src/main.rs \
    && cd gateway && cargo build --release || true
# Real sources.
COPY gateway ./gateway
RUN cd gateway && cargo build --release --locked \
    && strip target/release/zt-policy-gateway

# Distroless runtime: no shell, no package manager, runs as nonroot uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=build /src/gateway/target/release/zt-policy-gateway /app/zt-policy-gateway
USER nonroot:nonroot
EXPOSE 8443
# Config comes from env (see docker-compose.yml / k8s.yaml). Placeholders only.
ENTRYPOINT ["/app/zt-policy-gateway"]
