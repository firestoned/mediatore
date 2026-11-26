# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0

# The VM base image (ADR-0067): Kairos, Debian 13 and the OS layer the sandbox image
# (image/Dockerfile) and the gateway image (image/gateway/Dockerfile) share, and nothing of
# mediatore's. The two are overlays `FROM` this image. It is the part a site replaces with
# its own (a base kept in its own registry): an overlay built `--build-arg VM_BASE=<that
# image>` needs only what the overlays' prerequisite check names (`systemctl`, `useradd`,
# `apt-get`, nftables, tpm2-tools, qemu-guest-agent, the `tss` group, and no sshd).
#
# The one pin: the Kairos Debian 13 core base, by digest.
ARG KAIROS_BASE=quay.io/kairos/debian:13-core-amd64-generic-v3.7.2@sha256:9ec2c93da51dfdcd7a65ffb578089e2d278abb1ff210cbb7587f7cd3d6e7e523

FROM ${KAIROS_BASE}

# tpm2-tools: the EK certificate export banlieue's layer runs (its examples/21).
# qemu-guest-agent: the libvirt provider reads the VM's addresses and its EK certificate
# through it (ADR-0019); each overlay cuts its command set to what that takes with its own
# /etc/qemu/qemu-ga.conf.
# nftables: the jail's ruleset (ADR-0020) and the host tables (ADR-0027 decision 5,
# ADR-0029); the base has it, named so a base without it fails.
# Removed: every listener the base ships. Nothing inbound (ADR-0010 decision 2, ADR-0028
# decision 8, banlieue ADR-0109 decision 8).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tpm2-tools qemu-guest-agent nftables \
    && apt-get purge -y --auto-remove openssh-server openssh-sftp-server snmpd lldpd fail2ban rpcbind nfs-common \
    && rm -rf /var/lib/apt/lists/* \
    && ! command -v sshd \
    && systemctl mask ssh.service ssh.socket sshd.service
