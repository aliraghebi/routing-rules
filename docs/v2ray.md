# v2ray / Xray

`geosite.dat` and `geoip.dat` use the standard v2ray format, so they work in Xray, v2ray, v2rayN, v2rayNG
and other Xray-based apps.

Set these as the custom geo file URLs in your app:

=== "jsDelivr"

    `geosite.dat`

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geosite.dat
    ```

    `geoip.dat`

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geoip.dat
    ```

=== "GitHub"

    `geosite.dat`

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/geosite.dat
    ```

    `geoip.dat`

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/geoip.dat
    ```

To download the files instead, use GitHub Releases:
[geosite.dat](https://github.com/aliraghebi/vpn-routing/releases/latest/download/geosite.dat) ·
[geoip.dat](https://github.com/aliraghebi/vpn-routing/releases/latest/download/geoip.dat).

## Tags

| `geosite:` | `geoip:` |
|------------|----------|
| `ads`, `malware`, `phishing`, `cryptominers`, `sanctioned`, `ir`, `social`, `nsfw` | `ir`, `malware`, `phishing`, `private`, `cloudflare`, `cloudfront`, `fastly`, `gcore`, `telegram`, `tor`, `netflix` |

!!! warning "These files only contain the tags above"
    If you replace your app's stock geo files with these, rules that use other tags (`geosite:google`,
    `geoip:cn`, `geosite:category-ads-all`) stop working. Either update those rules, or keep the stock files
    and load these under another name (Xray only):

    ```
    ext:iran-geosite.dat:ads
    ext:iran-geoip.dat:ir
    ```

## Example routing

`xray-routing.json` follows the same order as the Shadowrocket config:

[:material-download: Download xray-routing.json](dl/xray-routing.json){ .md-button .md-button--primary download="xray-routing.json" }


```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:malware", "geosite:phishing", "geosite:cryptominers", "geosite:ads"], "outboundTag": "block" },
      { "type": "field", "ip": ["geoip:malware", "geoip:phishing"], "outboundTag": "block" },
      { "type": "field", "domain": ["geosite:sanctioned"], "outboundTag": "proxy" },
      { "type": "field", "domain": ["geosite:ir"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:ir"], "outboundTag": "direct" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  }
}
```

It expects outbounds tagged `proxy`, `direct` and `block` (blackhole). `IPIfNonMatch` resolves domains that
no domain rule matched, so `geoip:ir` also catches Iranian sites missing from `geosite:ir`.

## v2rayN / v2rayNG

These apps also need custom routing rules that use the tags. A ready-made rules file and import steps are
in the [v2rayN / v2rayNG guide](v2rayn.md).
