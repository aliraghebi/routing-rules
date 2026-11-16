# Karing

[Karing](https://karing.app) is built on sing-box and has its own format for custom diversion (routing) rules.
`karing.json` is a ready-made rules file in that format, using this project's sing-box rule-sets.

## Get the rules file

Pick the mirror you can reach. Each copy loads its rule-sets from the same mirror.

=== "jsDelivr"

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/karing-jsdelivr.json
    ```

=== "GitHub"

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/karing.json
    ```

## Import it

1. Download the file to your device.
2. In Karing, open the custom diversion rules screen and import the file. This is the same screen Karing
   exports `diversion_rules_custom.json` from.
3. Make sure both rule groups are switched on.

Karing downloads the rule-sets itself and refreshes them, so you don't need to re-import when the lists change.

## What it contains

| Group | Action | Rule-sets |
|-------|--------|-----------|
| 🚫 Block | `block` | `geosite-malware`, `geoip-malware`, `geosite-phishing`, `geoip-phishing`, `geosite-cryptominers`, `geosite-ads` |
| ✅ Direct | `direct` | `geosite-ir`, `geoip-ir`, `geoip-private` |

Everything else goes through the proxy you select in Karing. `geosite-ir` already includes the `.ir` and
`.ایران` TLDs, so you don't need a separate `.ir` rule.

!!! tip "Adding your own rules"
    You can add your own domains (for example `domain_suffix` or `domain_regex`) to either group in Karing.
    Importing a new copy of this file may replace those edits, so keep your own rules in a separate group.

To use more rule-sets (`geosite-nsfw`, `geoip-telegram`, …), add their `.srs` URLs to a group; see
[File URLs](urls.md#sing-box-rule-sets-binary).
