#!/usr/bin/env bash
# Apply validated observations to the `data` branch and push.
# Retries from a fresh clone if the push loses a race; applying is idempotent.
#
# Usage: commit-data.sh <collected-dir> <parsed-dir>
# Needs GITHUB_TOKEN (contents: write) and GITHUB_REPOSITORY.
set -euo pipefail

COLLECTED="${1:?collected directory}"
PARSED="${2:?parsed directory}"
: "${GITHUB_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
REMOTE="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

for attempt in 1 2 3; do
  rm -rf _data
  if ! git clone --quiet --depth 1 --branch data "$REMOTE" _data 2>/dev/null; then
    # First run: start the branch. If the clone failed for another reason the
    # push below is rejected (no force), and the loop retries.
    git init --quiet --initial-branch data _data
    git -C _data remote add origin "$REMOTE"
  fi
  python3 -m pipeline.commit --data _data --collected "$COLLECTED" --parsed "$PARSED"
  git -C _data add -A
  if git -C _data diff --cached --quiet; then
    echo "Nothing to commit."
    exit 0
  fi
  git -C _data \
    -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "data: $(date -u +%Y-%m-%dT%H:%M:%SZ) run ${GITHUB_RUN_ID:-local}"
  if git -C _data push --quiet origin data; then
    echo "Pushed."
    exit 0
  fi
  echo "Push failed (attempt ${attempt}); retrying from a fresh clone." >&2
  sleep $((attempt * 5))
done
exit 1
