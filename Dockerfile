# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# Server image. Static, distroless.
#
# BINARY_FROM selects where the musl binary comes from. `container` (the default,
# `make image`) compiles it inside the image from the source tree, so nothing but a
# container runtime is needed. `host` copies `dist/mediatore`, built by the host's
# cargo (`make dist`), so the kind tier reuses the host's build cache and still ships
# exactly this runtime stage.
ARG BINARY_FROM=container
# The compile stage's toolchain image (BINARY_FROM=container alone uses it; CI and the
# release copy dist/mediatore). A moving tag until it carries a digest: pin it here as
# <tag>@sha256:<digest>, from `crane digest docker.io/library/rust:1-slim`.
ARG RUST_IMG=rust:1-slim
# The runtime base, what the published server image is. A moving tag until it carries a
# digest: pin it here, from `crane digest cgr.dev/chainguard/static:latest`.
ARG STATIC_BASE=cgr.dev/chainguard/static:latest

FROM ${RUST_IMG} AS build-container
RUN rustup target add x86_64-unknown-linux-musl && apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p mediatore \
    && cp target/x86_64-unknown-linux-musl/release/mediatore /mediatore

FROM scratch AS build-host
COPY dist/mediatore /mediatore

FROM build-${BINARY_FROM} AS build

FROM ${STATIC_BASE}
COPY --from=build /mediatore /usr/bin/mediatore
USER 65532:65532
ENTRYPOINT ["/usr/bin/mediatore"]
CMD ["serve", "--config", "/etc/mediatore/mediatore.yaml"]
