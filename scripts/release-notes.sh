#!/usr/bin/env bash
# Prints release notes: when the release was built, and a table of rules added
# and removed per .list file compared with the previous release.
# Usage: release-notes.sh <previous release dir> <new release dir> <unix time>
set -euo pipefail
prev=$1 rel=$2 now=$3
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "- Updated on $(date -u -d "@$now" '+%A %Y-%m-%d %H:%M:%S UTC') from ${GITHUB_SHA::7}"
echo "- Always download from \`https://github.com/${GITHUB_REPOSITORY}/releases/latest/download/<file>\` to get latest version."
echo
echo
if ! ls "$prev"/*.list >/dev/null 2>&1; then
  echo "First release in this format; no previous lists to compare."
  exit 0
fi
rows=""
for f in "$rel"/*.list; do
  n=$(basename "$f")
  grep -v '^#' "$f" | LC_ALL=C sort > "$tmp/new.txt"
  { grep -v '^#' "$prev/$n" 2>/dev/null || true; } | LC_ALL=C sort > "$tmp/old.txt"
  add=$(LC_ALL=C comm -13 "$tmp/old.txt" "$tmp/new.txt" | wc -l)
  del=$(LC_ALL=C comm -23 "$tmp/old.txt" "$tmp/new.txt" | wc -l)
  if [ "$add" -gt 0 ] || [ "$del" -gt 0 ]; then
    rows+="| \`${n%.list}\` | $(( $(wc -l < "$tmp/new.txt") )) | +$(( add )) | −$(( del )) |"$'\n'
  fi
done
if [ -n "$rows" ]; then
  echo "| List | Rules | Added | Removed |"
  echo "|------|------:|------:|--------:|"
  printf '%s' "$rows"
else
  echo "Only non-list files changed (configs, formats or geo files)."
fi
