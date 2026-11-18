#!/usr/bin/env bash
# Print why the reviews of a PR block an automatic merge, or nothing when they don't: a change
# request from a writer (a later comment-only review doesn't withdraw it), or an unresolved
# review thread. Reviews or threads past the first 100 count against the merge.
#
# Usage: review_gate.sh <owner/repo> <PR number>, with GH_TOKEN able to read the PR.
set -euo pipefail

repo="$1"
number="$2"
review=$(gh api graphql -f owner="${repo%/*}" -f name="${repo#*/}" -F number="$number" -f query='
  query($owner: String!, $name: String!, $number: Int!) {
    repository(owner: $owner, name: $name) {
      pullRequest(number: $number) {
        reviewDecision
        latestOpinionatedReviews(first: 100, writersOnly: true) {
          totalCount
          nodes { state author { login } }
        }
        reviewThreads(first: 100) { totalCount nodes { isResolved } }
      }
    }
  }' --jq '.data.repository.pullRequest')

changes=$(jq -r '[.latestOpinionatedReviews.nodes[] | select(.state == "CHANGES_REQUESTED")
  | .author.login // "a deleted user"] | join(", ")' <<<"$review")
unchecked=$(jq -r '.latestOpinionatedReviews | .totalCount - (.nodes | length)' <<<"$review")
unresolved=$(jq -r '.reviewThreads | .totalCount - ([.nodes[] | select(.isResolved)] | length)' <<<"$review")

if [[ -n "$changes" || "$(jq -r '.reviewDecision // ""' <<<"$review")" == "CHANGES_REQUESTED" ]]; then
  echo "changes requested${changes:+ by $changes}"
elif (( unchecked > 0 )); then
  echo "more reviews than can be checked"
elif (( unresolved > 0 )); then
  echo "$unresolved unresolved review thread(s)"
fi
