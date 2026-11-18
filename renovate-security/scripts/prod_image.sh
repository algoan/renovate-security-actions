#!/usr/bin/env bash
# Describe the image currently carrying $TAG (default: prod) as key=value lines (GITHUB_OUTPUT
# format): digest, sha_tag, created and commit (empty when the commit is not in the local history).
set -euo pipefail

: "${FULL_IMAGE:?FULL_IMAGE must be set}"
TAG="${TAG:-prod}"

# `images list` only needs Artifact Registry read access, unlike `images describe`, which also
# queries Container Analysis.
image=$(gcloud artifacts docker images list "$FULL_IMAGE" --include-tags --format=json \
  | jq -c --arg tag "$TAG" '[.[] | select((.tags // [] | if type == "string" then split(",") else . end) | index($tag))] | first // empty')
if [[ -z "$image" ]]; then
  echo "No image tagged $TAG in $FULL_IMAGE" >&2
  exit 1
fi
digest=$(jq -r '.version' <<<"$image")

# Rebuild tags (sha-<commit>-rN) point to the same commit; distinct commits are ambiguous.
sha_tags=$(jq -r '(.tags | if type == "string" then split(",") else . end)[]' <<<"$image" \
  | grep -oE '^sha-[a-f0-9]{7,40}' | sort -u || true)
if (( $(grep -c . <<<"$sha_tags") > 1 )); then
  echo "The $TAG image carries tags of several commits ($(paste -sd, - <<<"$sha_tags")): its commit is ambiguous" >&2
  exit 1
fi
sha_tag="$sha_tags"
commit=""
if [[ -n "$sha_tag" ]]; then
  commit=$(git rev-parse --verify --quiet "${sha_tag#sha-}^{commit}" || true)
fi

echo "digest=$digest"
echo "sha_tag=$sha_tag"
echo "created=$(jq -r '.createTime' <<<"$image")"
echo "commit=$commit"
