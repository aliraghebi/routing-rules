# v2rayN / v2rayNG

`v2rayn-routing.json` is a set of custom routing rules in the JSON format v2rayN and v2rayNG import. It uses
this project's `geosite:` / `geoip:` tags.

[:material-download: Download v2rayn-routing.json](dl/v2rayn-routing.json){ .md-button .md-button--primary download="v2rayn-routing.json" }

To import by URL instead, use one of these:

=== "jsDelivr"

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/v2rayn-routing.json
    ```

=== "GitHub"

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/v2rayn-routing.json
    ```

## 1. Install the geo files first

The rules reference tags such as `geosite:ads` and `geoip:ir` that only exist in this project's
`geosite.dat` / `geoip.dat`. Set them up as described in the [v2ray / Xray guide](v2ray.md) before importing
the rules; otherwise the rules fail to load or match nothing.

## 2. Import the rules

Open the app's routing settings, add a new custom rule set, and import the downloaded file (or the URL above). Then select that rule set as the active routing.

!!! note
    Menu names differ between app versions and platforms. Look for **Routing setting** and an
    **Import rules** option.

## What it contains

| # | Match | Outbound |
|---|-------|----------|
| 1 | `geoip:private` | direct |
| 2 | `geosite:malware`, `geosite:phishing`, `geosite:cryptominers`, `geosite:ads` | block |
| 3 | `geoip:malware`, `geoip:phishing` | block |
| 4 | `geosite:sanctioned` | proxy |
| 5 | `geosite:ir` | direct |
| 6 | `geoip:ir` | direct |
| 7 | everything else | proxy |

The outbound tags are the standard `proxy`, `direct` and `block` that both apps use.
