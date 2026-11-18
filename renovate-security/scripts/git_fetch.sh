#!/usr/bin/env bash
# git fetch from origin authenticated with $FETCH_TOKEN for this command only: callers check out
# with persist-credentials: false, and nothing is written to the git config.
set -euo pipefail

: "${FETCH_TOKEN:?FETCH_TOKEN must be set}"
basic=$(printf 'x-access-token:%s' "$FETCH_TOKEN" | base64 | tr -d '\n')
echo "::add-mask::$basic"
exec git -c "http.${GITHUB_SERVER_URL:-https://github.com}/.extraheader=AUTHORIZATION: basic $basic" \
  fetch --no-tags origin "$@"
