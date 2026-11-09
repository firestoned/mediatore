#!/usr/bin/env python3
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
"""The research agent: reads a repository through the egress proxy, asks Claude about it
through the same proxy, writes a report to /work. It holds no credential: every request
carries the phantom from MEDIATORE_TOKEN, and the proxy outside the jail swaps it for what
the audience needs (a minted token, the operator's key) or drops it (ADR-0025 decision 8).

    research-agent <owner/repo> [question]
    research-agent --hello                 # one call to Claude, no repository

Environment, set by the guest: MEDIATORE_EGRESS_PROXY (http://127.0.0.1:3128) and
MEDIATORE_TOKEN (the phantom). Optional: RESEARCH_AGENT_MODEL (claude-opus-5-5),
RESEARCH_AGENT_GITHUB (api.github.com), RESEARCH_AGENT_ANTHROPIC (api.anthropic.com).
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PROXY = os.environ.get("MEDIATORE_EGRESS_PROXY", "http://127.0.0.1:3128").rstrip("/")
# Only http(s) leaves this process, and only through the proxy: the opener below has no
# file, ftp or data handler, and the proxy URL and the repository name are checked.
if urllib.parse.urlsplit(PROXY).scheme not in ("http", "https"):
    sys.exit(f"MEDIATORE_EGRESS_PROXY must be an http(s) URL, got {PROXY!r}")
OPENER = urllib.request.build_opener(urllib.request.HTTPHandler, urllib.request.HTTPSHandler)
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PHANTOM = os.environ.get("MEDIATORE_TOKEN", "")
MODEL = os.environ.get("RESEARCH_AGENT_MODEL", "claude-opus-5-5")
GITHUB = os.environ.get("RESEARCH_AGENT_GITHUB", "api.github.com")
ANTHROPIC = os.environ.get("RESEARCH_AGENT_ANTHROPIC", "api.anthropic.com")
REPORT = "/work/report.md"


def say(line: str) -> None:
    print(line, flush=True)


def github(path: str, accept: str = "application/vnd.github+json") -> tuple[int, str]:
    """One GET at GitHub's API through the proxy: the host is the first path segment, the
    phantom in Authorization (dropped by the proxy for a `via: none` audience)."""
    url = f"{PROXY}/{GITHUB}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {PHANTOM}",
            "Accept": accept,
            "User-Agent": "mediatore-research-agent",
        },
    )
    try:
        with OPENER.open(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def ask_claude(prompt: str) -> str:
    """One Messages call through the proxy. The SDK sends the phantom in x-api-key; the
    proxy recognises it there and places the operator's key (ADR-0032 decisions 2 and 3)."""
    import anthropic  # the SDK reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY

    os.environ["ANTHROPIC_BASE_URL"] = f"{PROXY}/{ANTHROPIC}"
    os.environ["ANTHROPIC_API_KEY"] = PHANTOM
    client = anthropic.Anthropic(max_retries=1, timeout=120.0)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIStatusError as e:
        # The proxy's refusals arrive as the status it answers: 401 unknown_credential,
        # 403 outside_rules, 404 no_route, 502 when the gateway refused the tunnel.
        return f"(claude unreachable: HTTP {e.status_code} {e.message})"
    except anthropic.APIConnectionError as e:
        return f"(claude unreachable: {e})"
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        return f"(claude declined: {getattr(details, 'category', None)})"
    say(
        f"PROOF claude model={response.model} stop={response.stop_reason} "
        f"input_tokens={response.usage.input_tokens} output_tokens={response.usage.output_tokens}"
    )
    return "".join(block.text for block in response.content if block.type == "text")


def main(argv: list[str]) -> int:
    say(f"research-agent proxy={PROXY} model={MODEL}")
    if not PHANTOM:
        say("no MEDIATORE_TOKEN in the environment: not in a sandbox?")
        return 2
    if len(argv) >= 1 and argv[0] == "--hello":
        answer = ask_claude(
            "In two sentences: you are being called from inside a network-jailed sandbox, "
            "through a credential-injecting proxy and an egress gateway. Say hello to the "
            "operator and name one thing you would check first in such a setup."
        )
        say(f"CLAUDE SAYS: {answer}")
        return 0
    if not argv:
        say(__doc__)
        return 2
    repo = argv[0]
    if not REPO_NAME.match(repo):
        say(f"not a repository name (owner/name): {repo!r}")
        return 2
    question = " ".join(argv[1:]) or "What is this project, and what would you look at first as a new contributor?"

    status, body = github(f"/repos/{repo}")
    say(f"PROOF github GET /repos/{repo}: HTTP {status}")
    if status != 200:
        say(body[:200])
        return 1
    meta = json.loads(body)
    status, readme = github(f"/repos/{repo}/readme", accept="application/vnd.github.raw+json")
    say(f"PROOF github GET /repos/{repo}/readme: HTTP {status} bytes={len(readme)}")
    if status != 200:
        readme = "(no readme)"

    prompt = (
        f"You are a research agent. Repository: {meta.get('full_name')}. "
        f"Description: {meta.get('description')}. Default branch: {meta.get('default_branch')}. "
        f"Stars: {meta.get('stargazers_count')}. Question: {question}\n\n"
        f"README (first 6000 characters):\n{readme[:6000]}\n\n"
        "Answer in under 200 words, as a short report with a heading."
    )
    answer = ask_claude(prompt)
    report = f"# {meta.get('full_name')}\n\n{answer}\n"
    try:
        with open(REPORT, "w", encoding="utf-8") as f:
            f.write(report)
        say(f"PROOF report written: {REPORT} bytes={len(report)}")
    except OSError as e:
        say(f"report not written: {e}")
    say("CLAUDE SAYS: " + answer.replace("\n", " ")[:600])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
