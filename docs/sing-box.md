# sing-box

Works with sing-box 1.11+ and apps built on it. Rule-sets are named like
[Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules): `geosite-<tag>` and
`geoip-<tag>`.

## Use the ready route

`sing-box-route.json` is a complete `route` block, in the same order as the Shadowrocket config:

=== "jsDelivr"

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/sing-box-route-jsdelivr.json
    ```

=== "GitHub"

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/sing-box-route.json
    ```

Copy its `route` object into your config. It expects outbounds tagged `proxy` and `direct`. Rule-sets are
downloaded through `proxy` (`download_detour`) and refreshed automatically.

## Or reference rule-sets yourself

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "geosite-ads",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geosite-ads.srs",
        "download_detour": "proxy"
      },
      {
        "tag": "geosite-ir",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geosite-ir.srs",
        "download_detour": "proxy"
      }
    ],
    "rules": [
      { "rule_set": "geosite-ads", "action": "reject" },
      { "rule_set": "geosite-ir", "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
```

Every `.srs` file also exists as `.json` for `"format": "source"`.

## Tags

| Domains (`geosite-…`) | IP ranges (`geoip-…`) |
|------------------------|------------------------|
| `ads`, `malware`, `phishing`, `cryptominers`, `sanctioned`, `ir`, `social`, `nsfw` | `ir`, `malware`, `phishing`, `private`, `cloudflare`, `cloudfront`, `fastly`, `gcore`, `telegram`, `tor`, `netflix` |

`geosite-ir` already includes the `.ir` and `.ایران` TLDs.

## Matching Iranian IPs

`geoip-ir` only matches connections that go to an IP address, like `no-resolve` in Shadowrocket. If you
also want domains resolved and matched by IP, add `{ "action": "resolve" }` before the `geoip-ir` rule. That
sends those DNS lookups through your configured DNS server.

All rule-set URLs: [File URLs](urls.md#sing-box-rule-sets-binary).
