#!/usr/bin/env bash
# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# Cancel the runs this event supersedes (`make ci-preempt`), so a hot fix is not queued
# behind work that no longer matters:
#
#   push (a merge to main)  cancels the queued or running pull_request runs of the PR
#                           the pushed commit merged, and of no other PR: an open PR's
#                           runs are still wanted, and nothing would restart them;
#   release                 cancels every queued or running push run on main.
#
# A GitHub Actions `concurrency` group only cancels within the same group, so crossing
# events is done here, with the API. Needs gh with a token that may write actions
# (GH_TOKEN; in CI the GITHUB_TOKEN of a job with `actions: write`) and GH_REPO
# (owner/name); for push, GITHUB_SHA, the pushed commit (set by Actions). Runs
# identically from a shell:
#
#   GH_REPO=firestoned/mediatore GITHUB_SHA=<merge commit> make ci-preempt CI_PREEMPT_EVENT=push
set -euo pipefail

event=${1:?usage: ci-preempt.sh push|release}
repo=${GH_REPO:?GH_REPO (owner/name) is not set}

# One query per set of runs to cancel.
queries=()
case "$event" in
  push)
    sha=${GITHUB_SHA:?GITHUB_SHA (the pushed commit) is not set}
    # The head branch of each PR the commit belongs to (a merge has one); a failed lookup
    # stops here and cancels nothing. `@uri`: a branch name goes into a query string.
    refs=$(gh api "repos/$repo/commits/$sha/pulls" --jq '.[].head.ref | @uri')
    while read -r ref; do
      [ -n "$ref" ] || continue
      queries+=("event=pull_request&branch=$ref")
    done <<< "$refs"
    if [ ${#queries[@]} -eq 0 ]; then
      echo "ci-preempt: no pull request is associated with $sha, nothing to cancel"
      exit 0
    fi
    ;;
  release) queries+=('event=push&branch=main') ;;
  *)
    echo "ci-preempt: unknown event '$event' (push or release)" >&2
    exit 2
    ;;
esac

cancelled=0
for query in "${queries[@]}"; do
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
done
echo "ci-preempt: cancelled $cancelled run(s) superseded by this $event"
