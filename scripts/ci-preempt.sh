#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Cancel the runs this event supersedes (`make ci-preempt`), so a hot fix is not queued
# behind work that no longer matters:
#
#   push (a merge to main)  cancels every queued or running pull_request run;
#   release                 cancels every queued or running push run on main.
#
# A GitHub Actions `concurrency` group only cancels within the same group, so crossing
# events is done here, with the API. Needs gh with a token that may write actions
# (GH_TOKEN; in CI the GITHUB_TOKEN of a job with `actions: write`) and GH_REPO
# (owner/name). Runs identically from a shell:
#
#   GH_REPO=firestoned/mediatore make ci-preempt CI_PREEMPT_EVENT=push
set -euo pipefail

event=${1:?usage: ci-preempt.sh push|release}
repo=${GH_REPO:?GH_REPO (owner/name) is not set}

case "$event" in
  push) query='event=pull_request' ;;
  release) query='event=push&branch=main' ;;
  *)
    echo "ci-preempt: unknown event '$event' (push or release)" >&2
    exit 2
    ;;
esac

cancelled=0
# Every status a run can have before it completes.
for status in queued in_progress waiting pending requested; do
  while read -r id name branch; do
    [ -n "$id" ] || continue
    echo "cancel $name #$id ($branch, $status)"
    if gh api -X POST "repos/$repo/actions/runs/$id/cancel" >/dev/null; then
      cancelled=$((cancelled + 1))
    else
      echo "  not cancelled (it finished first?)"
    fi
  done < <(gh api --paginate "repos/$repo/actions/runs?${query}&status=${status}&per_page=100" \
    --jq '.workflow_runs[] | "\(.id) \(.name | gsub(" "; "_")) \(.head_branch)"')
done
echo "ci-preempt: cancelled $cancelled run(s) superseded by this $event"
