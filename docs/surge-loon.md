# Surge and Loon

Surge and Loon read the same `RULE-SET` list format as Shadowrocket (`DOMAIN-SUFFIX,…`, `IP-CIDR,…,no-resolve`),
so they use the Shadowrocket `.list` files directly. There is no ready-made config for them; add the rules
below to your own config.

!!! warning "Not tested on device"
    These snippets follow each app's documented syntax but haven't been tested in Surge or Loon.

## Surge

Add these lines to the `[Rule]` section, above `FINAL`:

=== "jsDelivr"

    ```
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/malware.list,REJECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/phishing.list,REJECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/cryptominers.list,REJECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ads.list,REJECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/sanctioned.list,PROXY
    DOMAIN-SUFFIX,ir,DIRECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ir-domains.list,DIRECT
    RULE-SET,https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ir-cidr.list,DIRECT
    GEOIP,IR,DIRECT
    FINAL,PROXY
    ```

=== "GitHub"

    ```
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/malware.list,REJECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/phishing.list,REJECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/cryptominers.list,REJECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ads.list,REJECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/sanctioned.list,PROXY
    DOMAIN-SUFFIX,ir,DIRECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ir-domains.list,DIRECT
    RULE-SET,https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ir-cidr.list,DIRECT
    GEOIP,IR,DIRECT
    FINAL,PROXY
    ```

Replace `PROXY` with the name of your proxy or policy group.

## Loon

Add these lines to the `[Remote Rule]` section:

=== "jsDelivr"

    ```
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/malware.list, policy=REJECT, tag=malware, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/phishing.list, policy=REJECT, tag=phishing, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/cryptominers.list, policy=REJECT, tag=cryptominers, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ads.list, policy=REJECT, tag=ads, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/sanctioned.list, policy=PROXY, tag=sanctioned, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ir-domains.list, policy=DIRECT, tag=ir-domains, enabled=true
    https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release/ir-cidr.list, policy=DIRECT, tag=ir-cidr, enabled=true
    ```

=== "GitHub"

    ```
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/malware.list, policy=REJECT, tag=malware, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/phishing.list, policy=REJECT, tag=phishing, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/cryptominers.list, policy=REJECT, tag=cryptominers, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ads.list, policy=REJECT, tag=ads, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/sanctioned.list, policy=PROXY, tag=sanctioned, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ir-domains.list, policy=DIRECT, tag=ir-domains, enabled=true
    https://raw.githubusercontent.com/aliraghebi/vpn-routing/release/ir-cidr.list, policy=DIRECT, tag=ir-cidr, enabled=true
    ```

Then add `DOMAIN-SUFFIX,ir,DIRECT` and `GEOIP,IR,DIRECT` in `[Rule]`, and set `FINAL` to your proxy policy.
Replace `PROXY` with your policy group's name.
