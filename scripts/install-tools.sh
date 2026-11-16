#!/usr/bin/env bash
# Installs pinned sing-box, Xray and mihomo (linux-amd64) into $1, checking each
# download against the SHA-256 digest GitHub publishes for the release asset.
# Versions come from SING_BOX_VERSION, XRAY_VERSION and MIHOMO_VERSION. Needs gh.
set -euo pipefail
mkdir -p "$1"
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

get() {
  local repo=$1 tag=$2 asset=$3 want
  want=$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name == \"$asset\") | .digest")
  [ -n "$want" ] || { echo "::error::no published digest for $repo $tag $asset"; exit 1; }
  curl -fsSL -o "$asset" "https://github.com/$repo/releases/download/$tag/$asset"
  echo "${want#sha256:}  $asset" | sha256sum -c -
}

get SagerNet/sing-box "v$SING_BOX_VERSION" "sing-box-$SING_BOX_VERSION-linux-amd64.tar.gz"
tar xzf "sing-box-$SING_BOX_VERSION-linux-amd64.tar.gz" --strip-components=1 -C "$bin" "sing-box-$SING_BOX_VERSION-linux-amd64/sing-box"
get XTLS/Xray-core "v$XRAY_VERSION" Xray-linux-64.zip
unzip -q Xray-linux-64.zip xray -d "$bin"
get MetaCubeX/mihomo "v$MIHOMO_VERSION" "mihomo-linux-amd64-v$MIHOMO_VERSION.gz"
gunzip -c "mihomo-linux-amd64-v$MIHOMO_VERSION.gz" > "$bin/mihomo"
chmod +x "$bin/mihomo"
