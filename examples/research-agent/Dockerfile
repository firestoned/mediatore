# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The research agent of docs/guides/research-agent-walkthrough.md, as a real image: the
# runtime, the agent, its tools, and nothing of the sandbox machinery. No credential, no
# listener, no reliance on /proc or setuid (running-workloads.md). The guest mounts the one
# mediatore binary at /usr/bin/mediatore itself; the claim's workload.args is the argv.
#
# python:3.13-slim, pinned by digest (`crane digest docker.io/library/python:3.13-slim`).
FROM docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    # The jail drops setuid bits at the pull anyway (ADR-0021); the image ships none, so
    # what `make example-image` checks is what the workload gets.
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} +

# The Anthropic SDK: it reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY, which the agent
# points at the egress proxy and the phantom (ADR-0025, ADR-0032).
RUN pip install --no-cache-dir anthropic==1.17.0

COPY research_agent.py /usr/local/bin/research-agent
RUN chmod 0755 /usr/local/bin/research-agent

# A writable place the jail gives the workload (ADR-0021); the report goes here.
WORKDIR /work
# No ENTRYPOINT: the claim's workload.args is the argv, in full.
