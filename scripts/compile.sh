#!/usr/bin/env bash
# Compiles the rule-sets cmd/build wrote with the clients' own tools, in
# parallel: dist/geo*.json -> out/srs/*.srs (sing-box), out/clash/*.txt ->
# out/mrs/*.mrs (mihomo). Run from the repo root after `go run ./cmd/build`.
set -euo pipefail
jobs=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
rm -rf out/srs out/mrs
mkdir -p out/srs out/mrs

printf '%s\n' dist/geo*.json | xargs -P "$jobs" -n 1 sh -c '
  n=$(basename "${1%.json}")
  sing-box rule-set compile --output "out/srs/$n.srs" "$1"' _
for f in out/srs/*.srs; do
  [ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')" = "53525301" ] || { echo "::error::$f is not rule-set format version 1"; exit 1; }
done

printf '%s\n' out/clash/*.txt | xargs -P "$jobs" -n 1 sh -c '
  n=$(basename "${1%.txt}")
  case "$n" in geoip-*) b=ipcidr ;; *) b=domain ;; esac
  mihomo convert-ruleset "$b" text "$1" "out/mrs/$n.mrs"' _
for t in $(grep -oE 'url: .*/[^/]+\.mrs' dist/clash.yaml | sed -E 's#.*/##'); do
  [ -f "out/mrs/$t" ] || { echo "::error::clash.yaml references missing $t"; exit 1; }
done
echo "compiled $(ls out/srs | wc -l | tr -d ' ') .srs and $(ls out/mrs | wc -l | tr -d ' ') .mrs files"
