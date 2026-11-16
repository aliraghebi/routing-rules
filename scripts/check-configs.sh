#!/usr/bin/env bash
# Loads the generated route, DNS and rule configs into sing-box, Xray and
# mihomo with stand-in outbounds. Run after scripts/compile.sh.
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo '{"outbounds":[{"type":"direct","tag":"direct"},{"type":"direct","tag":"proxy"}]}' > "$tmp/sb-outbounds.json"
sing-box check -c "$tmp/sb-outbounds.json" -c dist/sing-box-route.json
sing-box check -c "$tmp/sb-outbounds.json" -c dist/sing-box-route.json -c dist/sing-box-dns.json

cat > "$tmp/xray-outbounds.json" <<'JSON'
{ "outbounds": [
    { "tag": "proxy", "protocol": "freedom" },
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" } ] }
JSON
XRAY_LOCATION_ASSET=out xray run -test -c "$tmp/xray-outbounds.json" -c dist/xray-routing.json
XRAY_LOCATION_ASSET=out xray run -test -c "$tmp/xray-outbounds.json" -c dist/xray-routing.json -c dist/xray-dns.json

mkdir -p "$tmp/mihomo"
{ cat dist/clash.yaml; echo; cat dist/clash-dns.yaml; echo
  echo 'proxy-groups:'; echo '  - {name: PROXY, type: select, proxies: [DIRECT]}'; } > "$tmp/mihomo/config.yaml"
timeout 120 mihomo -t -d "$tmp/mihomo" -f "$tmp/mihomo/config.yaml"
