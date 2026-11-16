# Shadowrocket

## Import the config

1. Copy the config URL:

    ```
    https://github.com/aliraghebi/vpn-routing/releases/latest/download/shadowrocket.conf
    ```

2. Shadowrocket → **Config** tab → **+** → paste the URL → **Download**.
3. Tap the new config → **Use Config**.
4. On the **Home** tab, add your server and set **Global Routing** to **Config**.

## Keep it updated

The lists change daily. The config includes `update-url` and every rule list is a remote `RULE-SET`, so you
don't need to re-import. To refresh, swipe left on the config in the **Config** tab → **Update**.

## Rule order

| # | Rule | Action |
|---|------|--------|
| 1 | `malware.list`, `phishing.list`, `cryptominers.list`, `ads.list`, `trackers.list` | REJECT |
| 2 | `sanctioned.list` | PROXY |
| 3 | `DOMAIN-SUFFIX,ir`, `ir-domains.list` | DIRECT |
| 4 | `ir-cidr.list` | DIRECT |
| 5 | `GEOIP,IR` | DIRECT |
| 6 | `FINAL` | PROXY |

## Add an optional list

Edit the config (**Config** → tap the config → **Edit Config** → **Rule**) and add a line above `FINAL`. For
example:

```
RULE-SET,https://github.com/aliraghebi/vpn-routing/releases/latest/download/nsfw.list,REJECT
RULE-SET,https://github.com/aliraghebi/vpn-routing/releases/latest/download/telegram.list,PROXY
```

!!! warning
    A local edit is lost when the config updates from `update-url`. To keep your changes, make your own
    config and only reference these lists with `RULE-SET` lines.

All list URLs: [File URLs](urls.md#shadowrocket-rule-lists).
