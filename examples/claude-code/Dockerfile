# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Claude Code as a sandbox workload (ADR-0035): the runtime, Claude Code, git, Python 3, Perl,
# the procps tools, and the one script that points it at the egress proxy with the phantom as
# its bearer. No credential, no listener, no setuid. The guest mounts the one mediatore binary
# itself; the claim's workload.args is the argv after `claude`.
#
# node:22 on Debian 13 (trixie), pinned by digest (`crane digest
# docker.io/library/node:22-trixie-slim`): trixie for Debian's newest Perl (5.40) and Python (3.13).
FROM docker.io/library/node:22-trixie-slim@sha256:f0960f8dc047f358e3fb428f36ccba21732194fa5f0cac849f401e63e62fb9e6

# python3 (and `python`, through python-is-python3) for the scripts Claude Code writes and
# runs; perl, the full interpreter and its standard library (the base has perl-base only);
# procps for `ps`, `top`, `pgrep` and `kill`, so it can see and stop what it started (the
# jail's /proc shows the workload's own processes only, ADR-0036).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
        python3 python-is-python3 perl procps \
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
