# vpn-routing

Rule lists for Shadowrocket, sing-box and v2ray/Xray, rebuilt every day by GitHub Actions from upstream sources.
It does what [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules) and
[Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules) do, from one pipeline:
Shadowrocket `RULE-SET` lists and config, sing-box rule-sets (`.srs` and JSON source), and v2ray `geosite.dat` /
`geoip.dat`. Legacy sing-box `.db` files are not built (sing-box removed geosite/geoip `.db` support in 1.12).

## Use it in Shadowrocket

1. Shadowrocket → **Config** → **+** (top right) → paste the config URL:
   - `https://raw.githubusercontent.com/aliraghebi/vpn-routing/main/dist/shadowrocket.conf`
   - or `https://github.com/aliraghebi/vpn-routing/releases/latest/download/shadowrocket.conf`
2. Tap the downloaded config → **Use Config**.
3. Add your proxy server on the Home tab and set **Global Routing** to **Config**.

The config's `update-url` points back to itself, and every `RULE-SET` is a URL, so Shadowrocket refreshes the
lists without a re-import (Config → long-press → Update, or enable auto-update in Settings).

### Rule order

| # | Rule | Action |
|---|------|--------|
| 1 | `malware`, `phishing`, `cryptominers`, `ads` | REJECT |
| 2 | `sanctioned` (sites that block Iranian IPs) | PROXY |
| 3 | `DOMAIN-SUFFIX,ir` + `ir-domains` | DIRECT |
| 4 | `ir-cidr` | DIRECT |
| 5 | `GEOIP,IR` | DIRECT |
| 6 | `FINAL` | PROXY |

### Lists in `dist/`

| File | In config | Contents |
|------|-----------|----------|
| `ads.list`, `malware.list`, `phishing.list`, `cryptominers.list` | yes (REJECT) | Blocklists |
| `sanctioned.list` | yes (PROXY) | Domains that refuse Iranian IPs |
| `ir-domains.list`, `ir-cidr.list` | yes (DIRECT) | Iranian domains and IP ranges |
| `social.list`, `nsfw.list` | no | Opt-in blocklists |
| `cloudflare`, `cloudfront`, `fastly`, `gcore`, `telegram`, `tor-exit`, `netflix` `.list` | no | Provider IP ranges |

To use an optional list, add a line to your own config, for example
`RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/main/dist/nsfw.list,REJECT` or
`RULE-SET,.../telegram.list,PROXY`.

## Use it in sing-box (1.11+)

Rule-sets are named like Chocolate4U's: `geosite-<tag>` and `geoip-<tag>`.

| Format | URL |
|--------|-----|
| Binary (recommended) | `https://github.com/aliraghebi/vpn-routing/releases/latest/download/geosite-ads.srs` |
| JSON source (`"format": "source"`, also works through jsDelivr) | `https://raw.githubusercontent.com/aliraghebi/vpn-routing/main/dist/sing-box/geosite-ads.json` |

[`dist/sing-box/route.json`](dist/sing-box/route.json) is a ready `route` block with the same order as the
Shadowrocket config. Merge it into your config; it expects outbounds tagged `proxy` and `direct`. `geoip-ir` only
matches connections to an IP (like `no-resolve`); add a `{"action": "resolve"}` rule before it if you want
domains resolved and matched by IP, which sends those DNS lookups through your configured DNS server.

Domain tags: `ads`, `malware`, `phishing`, `cryptominers`, `sanctioned`, `ir`, `social`, `nsfw`.
IP tags: `ir`, `malware`, `phishing`, `private`, `cloudflare`, `cloudfront`, `fastly`, `gcore`, `telegram`, `tor`,
`netflix`. `geosite-ir` already includes the `.ir` and `.ایران` TLDs.

## Use it in v2ray / Xray

Download `geosite.dat` and `geoip.dat` from
`https://github.com/aliraghebi/vpn-routing/releases/latest/download/` and use the tags as
`geosite:ads`, `geoip:ir`, and so on. [`dist/xray/routing.json`](dist/xray/routing.json) is an example
`routing` block (outbounds `proxy`, `direct`, `block`).

These files contain **only** the tags listed above, plus `geoip:private`. If you replace your client's stock
files with them, rules that use other tags (`geosite:google`, `geoip:cn`, `geosite:category-ads-all`) stop
working. To keep the stock files, save these under another name and reference them with Xray's `ext:` syntax,
e.g. `ext:iran-geosite.dat:ads` and `ext:iran-geoip.dat:ir`.

## Mirrors (raw.githubusercontent.com may be filtered in Iran)

The `RULE-SET` URLs are written into `shadowrocket.conf` at build time from `BASE_URL`. To serve everything from
a mirror, set the repository variable **Settings → Secrets and variables → Actions → Variables → `BASE_URL`**:

| Mirror | `BASE_URL` | Notes |
|--------|-----------|-------|
| GitHub raw (default) | `https://raw.githubusercontent.com/aliraghebi/vpn-routing/main/dist` | Updates within minutes; often filtered in Iran |
| jsDelivr | `https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@main/dist` | Caches branch URLs for up to 12 hours, so lists lag behind. Purge with `https://purge.jsdelivr.net/gh/aliraghebi/vpn-routing@main/dist/<file>` |
| jsDelivr alternate hosts | `https://fastly.jsdelivr.net/gh/aliraghebi/vpn-routing@main/dist`, `https://gcore.jsdelivr.net/gh/...` | Same cache behavior; different CDN edges, sometimes reachable when the main one is not |
| GitHub release assets | `https://github.com/aliraghebi/vpn-routing/releases/latest/download` | Redirects to `objects.githubusercontent.com`. The only place `.srs` and `.dat` are published |

You can also import the config from one mirror and keep the lists on another: the config URL and `BASE_URL` are
independent. Avoid untrusted "GitHub proxy" sites: they can rewrite the lists, and these lists control what goes
DIRECT (unencrypted to Iranian networks) versus through your proxy.

## Sources

All sources are in [`sources.yaml`](sources.yaml) with their URL, format, category, enabled flag and license.

| Category | Source | License |
|----------|--------|---------|
| ir-domains | [bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains) (`surge_domainset_other.txt`) | MIT |
| ir-domains | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) `category-ir` (without `category-ads-ir`) | MIT |
| ir-cidr | [ipdeny.com](https://www.ipdeny.com) IR aggregated zones (v4, v6) | ipdeny usage terms |
| ir-cidr | [RIPEstat](https://stat.ripe.net) country-resource-list IR | RIPEstat terms |
| ir-cidr | [ArvanCloud](https://www.arvancloud.ir/en/ips.txt), [ParsPack](https://parspack.com/cdnips.txt) CDN ranges | published by vendor |
| ir-cidr | MaxMind GeoLite2 Country (needs `MAXMIND_LICENSE_KEY` secret) | GeoLite2 EULA, CC BY-SA 4.0: "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com" |
| ir-cidr | IP2Location LITE DB1 (needs `IP2LOCATION_TOKEN` secret) | CC BY-SA 4.0: "This site or product includes IP2Location LITE data available from https://lite.ip2location.com" |
| ads | [MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker) | AGPL-3.0 |
| ads | v2fly `category-ads-ir`, bootmortis `surge_domainset_ads.txt`, local `ir-ads.txt` | MIT / this repo |
| ads | [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) Pro mini | GPL-3.0 |
| ads | [v2fly](https://github.com/v2fly/domain-list-community) `category-ads-all` | MIT |
| ads (off by default) | [jerryn70/GoodbyeAds](https://github.com/jerryn70/GoodbyeAds), [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | MIT, GPL-3.0 |
| malware | [URLhaus](https://urlhaus.abuse.ch) via [malware-filter/urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter) (hosts + IPs) | URLhaus CC0; filter MIT |
| phishing | [malware-filter/phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (hosts + IPs) | MIT; upstream feeds under own terms |
| cryptominers | [hoshsadiq/adblock-nocoin-list](https://github.com/hoshsadiq/adblock-nocoin-list) | MIT |
| social / nsfw | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) social-only / porn-only, v2fly `category-social-media-!cn` / `category-porn` | MIT |
| sanctioned | [MrDevAnony/DynX-AntiBan-Domains](https://github.com/MrDevAnony/DynX-AntiBan-Domains) | MIT |
| sanctioned | [filteryab/ir-sanctioned-domain](https://github.com/filteryab/ir-sanctioned-domain) | no license file upstream |
| providers | Cloudflare, AWS CloudFront, Fastly, G-Core, Telegram, Tor Project official feeds; [lord-alfred/ipranges](https://github.com/lord-alfred/ipranges) (CC0); Netflix = prefixes announced by AS2906 via RIPEstat | published by vendor / CC0 |

Configured but disabled (could not be verified, see the TODO in `sources.yaml`): ITO messenger IP list
(unreachable from outside Iran), Derak Cloud (page has no CIDRs in its HTML), IranServer CDN page (404).

**License of the output.** `ads.list` contains data from GPL-3.0 and AGPL-3.0 lists. Redistributing it means
the generated lists inherit those terms; pick a repository license compatible with them (GPL-3.0 or AGPL-3.0)
or disable those sources.

## How it works

```
sources.yaml ─► fetch (bounded concurrency, retries, size cap, ETag cache in .cache/)
             ─► parse (hosts | domains | abp | v2fly | cidr | html-cidr | json | maxmind-csv | ip2location)
             ─► merge (IDNA, validate, dedupe, drop DOMAIN-SUFFIX-covered entries, aggregate CIDRs)
             ─► safety checks ─► emit dist/*.list, dist/shadowrocket.conf,
                                       dist/sing-box/*.json, dist/xray/routing.json,
                                       out/geosite.dat, out/geoip.dat
CI only:     sing-box rule-set compile ─► out/srs/*.srs ─► checks ─► rolling release
```

`.srs` and `.dat` are binary and change daily, so they go only to the rolling release, not into git history.
Before anything is committed, CI compiles every rule-set with a pinned, checksum-verified sing-box. It then
checks known matches (`digikala.com` in `geosite-ir`, `yektanet.com` in `geosite-ads`, …) and runs
`sing-box check` on `route.json` and `xray run -test` on `routing.json` with the generated geo files.

Output is sorted, deduped and has no timestamps, so `git diff` only shows real changes.

Safety checks (they guard REJECT and DIRECT rules):

- A failing source falls back to its last-known-good copy in `.cache/sources/` (kept by `actions/cache`) with a warning.
- The build fails, leaving `dist/` untouched, if a list is below its `min_rules` or loses more than 30%
  (`max_shrink`) versus the committed file. Rerun with `ALLOW_SHRINK=1` (workflow_dispatch input) if intended.
- REJECT rules that would match an `allowlist.txt` domain are removed and reported as warnings.
- REJECT rules that would block a whole `ir-domains` entry, or REJECT CIDRs covering an `ir-cidr` range, are
  removed and logged as `filtered:`. More specific rules (blocking `ads.site.com` while `site.com` is DIRECT) stay.
- Exception: sources marked `override_direct: true` (PersianBlocker, v2fly `category-ads-ir`, bootmortis ads,
  and the hand-kept [`ir-ads.txt`](ir-ads.txt)) are trusted Iran ad lists. Their rules skip the check above, and
  `ir-domains` entries they cover are dropped, so Iranian ad networks (Yektanet, Tapsell, Adivery, Najva…) are
  blocked. Generic global lists still cannot block whole Iranian sites. To block another Iranian ad service, add it
  to `ir-ads.txt`; to rescue a site a trusted list wrongly blocks, add it to `allowlist.txt`.
- Prefixes broader than /8 (IPv4) or /16 (IPv6) are dropped from every list.
- A warning is printed when a list exceeds `list_cap_warn` rules; the iOS network extension has a tight memory limit.

## Add a source

1. Fetch the URL and check its real format; never guess a path.
2. Add an entry to `sources.yaml`:

   ```yaml
   - name: my-source            # unique; also the last-known-good cache key
     url: https://example.com/list.txt   # or file:///local.txt (repo root)
     format: domains            # hosts | domains | abp | v2fly | cidr | html-cidr | json | maxmind-csv | ip2location
     match: suffix              # hosts/domains only: suffix (DOMAIN-SUFFIX) or exact (DOMAIN, default)
     category: ads
     enabled: true
     max_rules: 0               # optional: keep only the first N rules (upstream order)
     override_direct: false     # REJECT only: trusted Iran ad list, wins over ir-domains
     license: MIT (owner/repo)
   ```

   Extra keys: `filter: {service: CLOUDFRONT}` (json), `country: IR` (GeoIP formats),
   `requires_env: [SECRET]` (skip when unset; `${SECRET}` in `url` is expanded and never logged),
   `skip_includes: [name]` (v2fly), `max_bytes` (size cap).
3. If it needs a new parser, add it to `internal/parse`, register it in `parse.Formats`, and add a fixture
   under `testdata/` plus a row in `TestParsers`.
4. `go test ./... && go run ./cmd/build` and check the summary table.

## Run locally

```sh
go test ./...
BASE_URL=https://raw.githubusercontent.com/aliraghebi/vpn-routing/main/dist go run ./cmd/build
```

`BASE_URL` overrides `settings.base_url` in `sources.yaml`, so local and CI builds produce the same config.
Optional secrets: `MAXMIND_LICENSE_KEY`, `IP2LOCATION_TOKEN`.

## GitHub Actions

`.github/workflows/build.yml` runs daily, on manual dispatch, and on pushes that touch code or `sources.yaml`.
It tests, builds, commits `dist/` only when something changed, and then updates the rolling `latest` release.
A keepalive job pushes an empty commit when the repo has had no commits for 50 days, because GitHub disables
scheduled workflows after 60 days of inactivity.

Set the secrets `MAXMIND_LICENSE_KEY` / `IP2LOCATION_TOKEN` (optional) and the variable `BASE_URL` (optional).
The workflow pushes to `main` with `GITHUB_TOKEN`; if `main` is protected, allow GitHub Actions to bypass.
Bot commits use `BOT_NAME` / `BOT_EMAIL` from the workflow's `env:` block.
