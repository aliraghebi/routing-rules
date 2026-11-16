# shadowrocket-config

A Shadowrocket config plus rule lists, rebuilt every day by GitHub Actions from upstream sources.
It does what [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules) and
[Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules) do, but writes Shadowrocket
text rule-sets instead of `.dat` / `.srs` / `.db` files.

## Use it in Shadowrocket

1. Shadowrocket → **Config** → **+** (top right) → paste the config URL:
   - `https://raw.githubusercontent.com/OWNER/REPO/main/dist/shadowrocket.conf`
   - or `https://github.com/OWNER/REPO/releases/latest/download/shadowrocket.conf`
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
`RULE-SET,https://raw.githubusercontent.com/OWNER/REPO/main/dist/nsfw.list,REJECT` or
`RULE-SET,.../telegram.list,PROXY`.

## Mirrors (raw.githubusercontent.com may be filtered in Iran)

The `RULE-SET` URLs are written into `shadowrocket.conf` at build time from `BASE_URL`. To serve everything from
a mirror, set the repository variable **Settings → Secrets and variables → Actions → Variables → `BASE_URL`**:

| Mirror | `BASE_URL` | Notes |
|--------|-----------|-------|
| GitHub raw (default) | `https://raw.githubusercontent.com/OWNER/REPO/main/dist` | Updates within minutes; often filtered in Iran |
| jsDelivr | `https://cdn.jsdelivr.net/gh/OWNER/REPO@main/dist` | Caches branch URLs for up to 12 hours, so lists lag behind. Purge with `https://purge.jsdelivr.net/gh/OWNER/REPO@main/dist/<file>` |
| jsDelivr alternate hosts | `https://fastly.jsdelivr.net/gh/OWNER/REPO@main/dist`, `https://gcore.jsdelivr.net/gh/...` | Same cache behavior; different CDN edges, sometimes reachable when the main one is not |
| GitHub release assets | `https://github.com/OWNER/REPO/releases/latest/download` | Redirects to `objects.githubusercontent.com` |

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
             ─► safety checks ─► emit dist/*.list + dist/shadowrocket.conf
```

Output is sorted, deduped and has no timestamps, so `git diff` only shows real changes.

Safety checks (they guard REJECT and DIRECT rules):

- A failing source falls back to its last-known-good copy in `.cache/sources/` (kept by `actions/cache`) with a warning.
- The build fails, leaving `dist/` untouched, if a list is below its `min_rules` or loses more than 30%
  (`max_shrink`) versus the committed file. Rerun with `ALLOW_SHRINK=1` (workflow_dispatch input) if intended.
- REJECT rules that would match an `allowlist.txt` domain are removed and reported as warnings.
- REJECT rules that would block a whole `ir-domains` entry, or REJECT CIDRs covering an `ir-cidr` range, are
  removed and logged as `conflict:`. More specific rules (blocking `ads.site.com` while `site.com` is DIRECT) stay.
- Prefixes broader than /8 (IPv4) or /16 (IPv6) are dropped from every list.
- A warning is printed when a list exceeds `list_cap_warn` rules; the iOS network extension has a tight memory limit.

## Add a source

1. Fetch the URL and check its real format; never guess a path.
2. Add an entry to `sources.yaml`:

   ```yaml
   - name: my-source            # unique; also the last-known-good cache key
     url: https://example.com/list.txt
     format: domains            # hosts | domains | abp | v2fly | cidr | html-cidr | json | maxmind-csv | ip2location
     match: suffix              # hosts/domains only: suffix (DOMAIN-SUFFIX) or exact (DOMAIN, default)
     category: ads
     enabled: true
     max_rules: 0               # optional: keep only the first N rules (upstream order)
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
BASE_URL=https://raw.githubusercontent.com/OWNER/REPO/main/dist go run ./cmd/build
```

Without `BASE_URL` or `GITHUB_REPOSITORY`, the config uses an `OWNER/REPO` placeholder and prints a warning.
Optional secrets: `MAXMIND_LICENSE_KEY`, `IP2LOCATION_TOKEN`.

## GitHub Actions

`.github/workflows/build.yml` runs daily, on manual dispatch, and on pushes that touch code or `sources.yaml`.
It tests, builds, commits `dist/` only when something changed, and then updates the rolling `latest` release.
A keepalive job pushes an empty commit when the repo has had no commits for 50 days, because GitHub disables
scheduled workflows after 60 days of inactivity.

Set the secrets `MAXMIND_LICENSE_KEY` / `IP2LOCATION_TOKEN` (optional) and the variable `BASE_URL` (optional).
The workflow pushes to `main` with `GITHUB_TOKEN`; if `main` is protected, allow `github-actions[bot]` to bypass.
