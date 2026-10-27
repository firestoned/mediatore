# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# The sandbox VM image: a Kairos derivative (ADR-0023). What every pool member boots.
#
# Everything the guest needs is in the immutable rootfs: the one mediatore binary at the
# pinned path, the SPIRE agent and its TPM attestor plugin, the packages, the units, the
# spire user. Nothing deployment-specific (trust bundle, trust domain, server address) and
# nothing per VM (keys) is here; those are the cloud-config layers (image/cloud-config.yaml
# and image/cloud-config-deployment.example.yaml) and the member's sealed partition.
#
# BINARY_FROM, as for the server image: `container` compiles mediatore in the build,
# `host` copies dist/mediatore (`make dist`). The other three ARGs are pins, by digest;
# the plugin's checksum is verified against the one image/spire/agent.conf carries.
ARG BINARY_FROM=container
ARG KAIROS_BASE=quay.io/kairos/debian:13-core-amd64-generic-v3.7.2@sha256:9ec2c93da51dfdcd7a65ffb578089e2d278abb1ff210cbb7587f7cd3d6e7e523
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

FROM ${SPIRE_AGENT_IMG} AS spire-agent
FROM ${TPM_PLUGIN_AGENT_IMG} AS tpm-plugin

FROM ${KAIROS_BASE}
ARG TPM_PLUGIN_AGENT_SHA

# tpm2-tools: the EK certificate export banlieue's layer runs (its examples/21).
# qemu-guest-agent: the libvirt provider reads /run/banlieue through it (ADR-0019).
# nftables: the jail's ruleset (ADR-0020); the base has it, named so a base without it fails.
# Removed: every listener the base ships. Nothing inbound (ADR-0010 decision 2).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tpm2-tools qemu-guest-agent nftables \
    && apt-get purge -y --auto-remove openssh-server openssh-sftp-server snmpd lldpd fail2ban rpcbind nfs-common \
    && rm -rf /var/lib/apt/lists/* \
    && ! command -v sshd

# The agent runs unprivileged, in the TPM device group (image/systemd/spire-agent.service).
RUN useradd --system --user-group --home-dir /var/lib/spire --no-create-home --shell /usr/sbin/nologin spire \
    && usermod -aG tss spire

COPY --from=build /mediatore /usr/bin/mediatore
COPY --from=spire-agent /opt/spire/bin/spire-agent /usr/bin/spire-agent
COPY --from=tpm-plugin /app/tpm_attestor_agent /usr/lib/spire/tpm_attestor_agent
RUN chmod 0755 /usr/bin/mediatore /usr/bin/spire-agent /usr/lib/spire/tpm_attestor_agent \
    && echo "${TPM_PLUGIN_AGENT_SHA}  /usr/lib/spire/tpm_attestor_agent" | sha256sum -c -

COPY image/systemd/spire-agent.service image/systemd/mediatore-guest.service /etc/systemd/system/
COPY image/spire/agent.conf /usr/share/mediatore/agent.conf.example
RUN grep -q "plugin_checksum = \"${TPM_PLUGIN_AGENT_SHA}\"" /usr/share/mediatore/agent.conf.example \
    && systemctl enable spire-agent.service mediatore-guest.service qemu-guest-agent.service \
    && systemctl mask ssh.service ssh.socket sshd.service
