# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# The egress gateway VM image: a Kairos derivative like the sandbox image (ADR-0023), for
# the three proxy VMs of banlieue ADR-0109 (ADR-0028 decision 10). What every gateway boots.
#
# In the immutable rootfs: Envoy from its official image, pinned by digest and checked to
# run; the one mediatore binary (its gateway role is the authorizer, ADR-0028 decision 4);
# the SPIRE agent and its TPM attestor plugin (the gateway attests like a sandbox, decision
# 2); nftables for the host table (ADR-0027 decision 5); the templates the units render at
# every start, the units themselves, and the four service users: envoy (the data plane),
# envoy-relay (the control relay, ADR-0027 decision 1, never in the agent's group and
# kept out of /run/spire by its unit), envoy-inject (the inject listener, ADR-0040: it
# originates TLS to a fixed upstream and holds a credential only for one request; its
# unit is installed and NOT enabled, a deployment turns it on) and mediatore-gateway
# (the authorizer). Nothing
# deployment-specific (trust domain, upstream addresses, bundle) and nothing per VM (the
# sandbox address, keys) is here: those are the cloud-config layers
# (image/gateway/cloud-config.yaml, cloud-config-deployment.example.yaml), the VM's
# userData (vm.env) and the member's sealed partition. No sshd, no forwarding, no admin
# interface (decision 8).
#
# An overlay (ADR-0067), like the sandbox image: `FROM` the VM base (image/base/Dockerfile,
# or a site's own base by VM_BASE), which carries the OS layer (Kairos, Debian 13,
# tpm2-tools, qemu-guest-agent, nftables, no listener); this file adds mediatore's pieces
# only, pulled from their images.
#
# BINARY_FROM as for the sandbox image: `image` (the default) copies /usr/bin/mediatore
# out of the mediatore container image MEDIATORE_IMG, `container` compiles mediatore in the
# build, `host` copies dist/mediatore (`make dist`). The pins: the mediatore image, Envoy
# (the same digest dev/kind/gateway/kustomization.yaml runs the tier against; a bump is
# both files and the tier again), the SPIRE agent and the plugin, whose checksum is
# verified against image/spire/agent.conf.
ARG BINARY_FROM=image
# The VM base this overlays (image/base/Dockerfile, `make base-image`). A moving tag until
# the Build workflow has published it: pin it here as <tag>@sha256:<digest> then, from
# `crane digest ghcr.io/firestoned/mediatore-vm-base:latest`. CI builds against the base
# it publishes in the same run, by digest.
ARG VM_BASE=ghcr.io/firestoned/mediatore-vm-base:latest
# The mediatore container image BINARY_FROM=image takes the binary from (the static musl
# build at /usr/bin/mediatore, the root Dockerfile). Bump it with the release the gateways run.
ARG MEDIATORE_IMG=ghcr.io/firestoned/mediatore:sha-4c653fb@sha256:3e1ff6061d83047f163261b6b30b58b17508bde33caff9a0a2c5df931e92ea6e
ARG ENVOY_IMG=docker.io/envoyproxy/envoy:v1.40.2@sha256:49d3e8b6246d1a804acffaebe42f2799edc77b77a37a97709ef742af90b6d223
ARG SPIRE_AGENT_IMG=ghcr.io/spiffe/spire-agent:1.15.3@sha256:41b0dcd8b258a69db9e2768292a060766fb76fd866e4bc925849981ea1b825ff
ARG TPM_PLUGIN_AGENT_IMG=ghcr.io/spiffe/spire-tpm-plugin-tpm-attestor-agent:v1.11.3@sha256:4dba6dc77fcec06b66962b632b6453636d49d51a38946efb0bc6fed29e4b75b1
ARG TPM_PLUGIN_AGENT_SHA=ffb7e266c7a10a7b1bdb349409d6c2ded8090715770287813055431cb692575c
# The compile stage's toolchain image (BINARY_FROM=container alone uses it; CI and the
# release copy dist/mediatore). A moving tag until it carries a digest: pin it here as
# <tag>@sha256:<digest>, from `crane digest docker.io/library/rust:1-slim`.
ARG RUST_IMG=rust:1-slim

FROM ${RUST_IMG} AS build-container
RUN rustup target add x86_64-unknown-linux-musl && apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p mediatore \
    && cp target/x86_64-unknown-linux-musl/release/mediatore /mediatore

FROM scratch AS build-host
COPY dist/mediatore /mediatore

FROM ${MEDIATORE_IMG} AS mediatore-image
FROM scratch AS build-image
COPY --from=mediatore-image /usr/bin/mediatore /mediatore

FROM build-${BINARY_FROM} AS build

FROM ${ENVOY_IMG} AS envoy
FROM ${SPIRE_AGENT_IMG} AS spire-agent
FROM ${TPM_PLUGIN_AGENT_IMG} AS tpm-plugin

FROM ${VM_BASE}
ARG TPM_PLUGIN_AGENT_SHA

# What this overlay needs of its base, checked so a site's own base fails here, at build
# time, rather than on a gateway: the tools the units and the build call, the packages the
# base layer installs (tpm2-tools for the EK export, qemu-guest-agent for the libvirt
# channel, cut to what that takes by image/gateway/qemu-ga.conf below, nftables for the
# host table, ADR-0027 decision 5), the TPM device group, and no sshd (ADR-0028 decision 8,
# banlieue ADR-0109 decision 8).
RUN command -v systemctl && command -v useradd && command -v nft \
    && command -v tpm2_nvread && command -v qemu-ga && getent group tss \
    && ! command -v sshd

# The agent in the TPM device group (image/systemd/spire-agent.service); the four service
# users with no group in common and no login (a socket group is what lets an Envoy reach the
# authorizer: ADR-0040 decision 6). Only the agent touches the TPM.
RUN useradd --system --user-group --home-dir /var/lib/spire --no-create-home --shell /usr/sbin/nologin spire \
    && usermod -aG tss spire \
    && for u in envoy envoy-relay envoy-inject mediatore-gateway; do \
         useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$u"; \
       done

RUN install -d -m 0755 /etc/spire /etc/mediatore-gateway /usr/share/mediatore-gateway/envoy /usr/libexec/mediatore-gateway

COPY --from=build /mediatore /usr/bin/mediatore
COPY --from=envoy /usr/local/bin/envoy /usr/bin/envoy
COPY --from=spire-agent /opt/spire/bin/spire-agent /usr/bin/spire-agent
COPY --from=tpm-plugin /app/tpm_attestor_agent /usr/lib/spire/tpm_attestor_agent
RUN chmod 0755 /usr/bin/mediatore /usr/bin/envoy /usr/bin/spire-agent /usr/lib/spire/tpm_attestor_agent \
    && echo "${TPM_PLUGIN_AGENT_SHA}  /usr/lib/spire/tpm_attestor_agent" | sha256sum -c - \
    && /usr/bin/envoy --version | grep -q "1.40.2"

COPY image/gateway/render /usr/libexec/mediatore-gateway/render
COPY image/gateway/envoy/gateway.yaml.in image/gateway/envoy/relay.yaml.in image/gateway/envoy/inject.yaml.in /usr/share/mediatore-gateway/envoy/
COPY image/gateway/nftables.conf.in image/gateway/network.in image/gateway/env.example image/gateway/env.inject.example image/gateway/vm.env.example /usr/share/mediatore-gateway/
COPY image/gateway/systemd/spire-agent.service \
     image/gateway/systemd/mediatore-gateway-network.service \
     image/gateway/systemd/mediatore-gateway-nft.service \
     image/gateway/systemd/envoy-gateway.service \
     image/gateway/systemd/envoy-relay.service \
     image/gateway/systemd/envoy-inject.service \
     image/gateway/systemd/mediatore-gateway.service \
     /etc/systemd/system/
COPY image/gateway/sysctl/99-mediatore-gateway.conf /etc/sysctl.d/99-mediatore-gateway.conf
# The guest agent answers the commands banlieue's provider sends and no other: no exec, no
# file write (threat model R-43).
COPY image/gateway/qemu-ga.conf /etc/qemu/qemu-ga.conf
COPY image/spire/agent.conf /usr/share/mediatore/agent.conf.example
# The examples render every template completely: a placeholder nobody documents fails the build.
RUN chmod 0755 /usr/libexec/mediatore-gateway/render \
    && for t in envoy/gateway.yaml.in envoy/relay.yaml.in envoy/inject.yaml.in nftables.conf.in network.in; do \
         /usr/libexec/mediatore-gateway/render "/usr/share/mediatore-gateway/$t" - /usr/share/mediatore-gateway/env.example /usr/share/mediatore-gateway/vm.env.example > /dev/null; \
       done \
    && grep -q "plugin_checksum = \"${TPM_PLUGIN_AGENT_SHA}\"" /usr/share/mediatore/agent.conf.example \
    && systemctl enable spire-agent.service mediatore-gateway-network.service mediatore-gateway-nft.service \
         envoy-gateway.service envoy-relay.service mediatore-gateway.service qemu-guest-agent.service \
    && systemctl mask ssh.service ssh.socket sshd.service nftables.service
