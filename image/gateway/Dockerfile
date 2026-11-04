# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# The egress gateway VM image: a Kairos derivative like the sandbox image (ADR-0023), for
# the three proxy VMs of banlieue ADR-0109 (ADR-0028 decision 10). What every gateway boots.
#
# In the immutable rootfs: Envoy from its official image, pinned by digest and checked to
# run; the one mediatore binary (its gateway role is the authorizer, ADR-0028 decision 4);
# the SPIRE agent and its TPM attestor plugin (the gateway attests like a sandbox, decision
# 2); nftables for the host table (ADR-0027 decision 5); the templates the units render at
# every start, the units themselves, and the three service users: envoy (the data plane),
# envoy-relay (the control relay, ADR-0027 decision 1, never in the agent's group and
# kept out of /run/spire by its unit) and mediatore-gateway (the authorizer). Nothing
# deployment-specific (trust domain, upstream addresses, bundle) and nothing per VM (the
# sandbox address, keys) is here: those are the cloud-config layers
# (image/gateway/cloud-config.yaml, cloud-config-deployment.example.yaml), the VM's
# userData (vm.env) and the member's sealed partition. No sshd, no forwarding, no admin
# interface (decision 8).
#
# BINARY_FROM as for the sandbox image: `container` compiles mediatore in the build, `host`
# copies dist/mediatore (`make dist`). The pins: the Kairos base, Envoy (the same digest
# dev/kind/gateway/kustomization.yaml runs the tier against; a bump is both files and the
# tier again), the SPIRE agent and the plugin, whose checksum is verified against
# image/spire/agent.conf.
ARG BINARY_FROM=container
ARG KAIROS_BASE=quay.io/kairos/debian:13-core-amd64-generic-v3.7.2@sha256:9ec2c93da51dfdcd7a65ffb578089e2d278abb1ff210cbb7587f7cd3d6e7e523
ARG ENVOY_IMG=docker.io/envoyproxy/envoy:v1.40.2@sha256:49d3e8b6246d1a804acffaebe42f2799edc77b77a37a97709ef742af90b6d223
ARG SPIRE_AGENT_IMG=ghcr.io/spiffe/spire-agent:1.15.3@sha256:41b0dcd8b258a69db9e2768292a060766fb76fd866e4bc925849981ea1b825ff
ARG TPM_PLUGIN_AGENT_IMG=ghcr.io/spiffe/spire-tpm-plugin-tpm-attestor-agent:v1.11.3@sha256:4dba6dc77fcec06b66962b632b6453636d49d51a38946efb0bc6fed29e4b75b1
ARG TPM_PLUGIN_AGENT_SHA=ffb7e266c7a10a7b1bdb349409d6c2ded8090715770287813055431cb692575c

FROM rust:1-slim AS build-container
RUN rustup target add x86_64-unknown-linux-musl && apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p mediatore \
    && cp target/x86_64-unknown-linux-musl/release/mediatore /mediatore

FROM scratch AS build-host
COPY dist/mediatore /mediatore

FROM build-${BINARY_FROM} AS build

FROM ${ENVOY_IMG} AS envoy
FROM ${SPIRE_AGENT_IMG} AS spire-agent
FROM ${TPM_PLUGIN_AGENT_IMG} AS tpm-plugin

FROM ${KAIROS_BASE}
ARG TPM_PLUGIN_AGENT_SHA

# tpm2-tools: the EK certificate export banlieue's layer runs (its examples/21).
# qemu-guest-agent: the libvirt provider reads the VM's addresses through it.
# nftables: the host table (ADR-0027 decision 5); the base has it, named so a base
# without it fails.
# Removed: every listener the base ships. Nothing inbound but the two planes (ADR-0028
# decision 8, banlieue ADR-0109 decision 8).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tpm2-tools qemu-guest-agent nftables \
    && apt-get purge -y --auto-remove openssh-server openssh-sftp-server snmpd lldpd fail2ban rpcbind nfs-common \
    && rm -rf /var/lib/apt/lists/* \
    && ! command -v sshd

# The agent in the TPM device group (image/systemd/spire-agent.service); the three service
# users with no group in common and no login. Only the agent touches the TPM.
RUN useradd --system --user-group --home-dir /var/lib/spire --no-create-home --shell /usr/sbin/nologin spire \
    && usermod -aG tss spire \
    && for u in envoy envoy-relay mediatore-gateway; do \
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
COPY image/gateway/envoy/gateway.yaml.in image/gateway/envoy/relay.yaml.in /usr/share/mediatore-gateway/envoy/
COPY image/gateway/nftables.conf.in image/gateway/network.in image/gateway/env.example image/gateway/vm.env.example /usr/share/mediatore-gateway/
COPY image/systemd/spire-agent.service \
     image/gateway/systemd/mediatore-gateway-network.service \
     image/gateway/systemd/mediatore-gateway-nft.service \
     image/gateway/systemd/envoy-gateway.service \
     image/gateway/systemd/envoy-relay.service \
     image/gateway/systemd/mediatore-gateway.service \
     /etc/systemd/system/
COPY image/gateway/sysctl/99-mediatore-gateway.conf /etc/sysctl.d/99-mediatore-gateway.conf
COPY image/spire/agent.conf /usr/share/mediatore/agent.conf.example
# The examples render every template completely: a placeholder nobody documents fails the build.
RUN chmod 0755 /usr/libexec/mediatore-gateway/render \
    && for t in envoy/gateway.yaml.in envoy/relay.yaml.in nftables.conf.in network.in; do \
         /usr/libexec/mediatore-gateway/render "/usr/share/mediatore-gateway/$t" - /usr/share/mediatore-gateway/env.example /usr/share/mediatore-gateway/vm.env.example > /dev/null; \
       done \
    && grep -q "plugin_checksum = \"${TPM_PLUGIN_AGENT_SHA}\"" /usr/share/mediatore/agent.conf.example \
    && systemctl enable spire-agent.service mediatore-gateway-network.service mediatore-gateway-nft.service \
         envoy-gateway.service envoy-relay.service mediatore-gateway.service qemu-guest-agent.service \
    && systemctl mask ssh.service ssh.socket sshd.service nftables.service
