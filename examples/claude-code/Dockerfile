# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Claude Code as a sandbox workload (ADR-0035): the runtime, Claude Code, git, and the one
# script that points it at the egress proxy with the phantom as its bearer. No credential,
# no listener, no setuid. The guest mounts the one mediatore binary itself; the claim's
# workload.args is the argv after `claude`.
#
# node:22-slim, pinned by digest (`crane digest docker.io/library/node:22-slim`).
FROM docker.io/library/node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # The jail drops setuid bits at the pull anyway (ADR-0021); the image ships none.
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} +

# Claude Code, pinned; it reads CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_BASE_URL. Its
# install script places the platform's native binary, so scripts run here.
RUN npm install -g @anthropic-ai/claude-code@2.1.322 \
    && npm cache clean --force

COPY claude-sandbox /usr/local/bin/claude-sandbox
RUN chmod 0755 /usr/local/bin/claude-sandbox

# A writable place the jail gives the workload (ADR-0021).
WORKDIR /work
# No ENTRYPOINT: the claim's workload.args is the argv, in full:
#   --arg /usr/local/bin/claude-sandbox --arg=-p --arg "<prompt>"
