#!/usr/bin/env bash
# Publishes the files in $REL as a new GitHub release (draft until every file
# is uploaded, then latest) and keeps only the 7 newest releases.
# Usage: publish.sh <previous release dir>. Needs gh, GH_TOKEN and REL.
set -euo pipefail
prev=$1
now=$(date -u +%s)
tag=$(date -u -d "@$now" +%Y%m%d%H%M)
if gh release view "$tag" >/dev/null 2>&1; then tag=$(date -u -d "@$now" +%Y%m%d%H%M%S); fi
notes=$("$(dirname "$0")/release-notes.sh" "$prev" "$REL" "$now")
gh release create "$tag" --draft --target "$GITHUB_SHA" --title "$(date -u -d "@$now" '+%Y-%m-%d %H:%M UTC')" --notes "$notes"
gh release upload "$tag" "$REL"/*
gh release edit "$tag" --draft=false --latest
gh release list --limit 200 --json tagName,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[7:] | .[].tagName' |
while read -r old; do
  gh release delete "$old" --yes --cleanup-tag || echo "::warning::could not delete release $old"
done
