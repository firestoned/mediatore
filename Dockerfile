# Server image. Static, distroless.
FROM rust:1-slim AS build
RUN rustup target add x86_64-unknown-linux-musl && apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p mediatore

FROM cgr.dev/chainguard/static:latest
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/mediatore /usr/local/bin/mediatore
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mediatore"]
CMD ["serve", "--config", "/etc/mediatore/mediatore.yaml"]
