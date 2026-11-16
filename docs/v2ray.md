# v2ray / Xray

`geosite.dat` and `geoip.dat` use the standard v2ray format, so they work in Xray, v2ray, v2rayN, v2rayNG
and other Xray-based apps.

| File | GitHub | jsDelivr |
|------|--------|----------|
| `geosite.dat` | `https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/geosite.dat` | `https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geosite.dat` |
| `geoip.dat` | `https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/geoip.dat` | `https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/geoip.dat` |

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

- **v2rayNG**: Settings → **Geo asset files** → set the custom URLs for `geosite.dat` and `geoip.dat` to the
  links above, then update. Use the `geosite:`/`geoip:` tags in your routing rules.
- **v2rayN**: put the files in the app's `bin` folder (replacing the stock ones), or set custom geo file URLs
  in the settings if your version has them. Then add routing rules with the tags above.

!!! note
    Menu names change between app versions; look for "geo files" or "asset files" in the settings.
