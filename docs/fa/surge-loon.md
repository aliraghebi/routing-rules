---
icon: material/waves
---

# Surge و Loon

Surge و Loon همان قالب فهرست `RULE-SET` مربوط به Shadowrocket را می‌خوانند (`DOMAIN-SUFFIX,…`،
`IP-CIDR,…,no-resolve`)، پس مستقیم از فایل‌های `.list` مربوط به Shadowrocket استفاده می‌کنند. پیکربندی
آماده‌ای برای آن‌ها وجود ندارد؛ قوانین زیر را به پیکربندی خودتان اضافه کنید.

!!! warning "روی دستگاه آزموده نشده"
    این قطعه‌ها طبق نحو مستند هر برنامه نوشته شده‌اند، اما در Surge یا Loon آزموده نشده‌اند.

## Surge

سریع‌ترین راه، ماژول است که همه قوانین زیر را روی پیکربندی شما اضافه می‌کند:

```
https://github.com/aliraghebi/routing-rules/releases/latest/download/routing-rules.sgmodule
```

آن را از **Modules** ← **Install New Module** با همین نشانی نصب کنید. قوانین، سایت‌هایی را که IP ایران را
مسدود می‌کنند به policy با نام `PROXY` می‌فرستند؛ یک policy group با همین نام بسازید، یا اگر نام گروه شما فرق
دارد، نسخه‌ای از ماژول را ویرایش کنید.

برای افزودن دستی قوانین، این خطوط را در بخش `[Rule]`، بالای `FINAL`، اضافه کنید:

```
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-injected.list,REJECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/malware.list,REJECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/phishing.list,REJECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/cryptominers.list,REJECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/ads.list,REJECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/sanctioned.list,PROXY
DOMAIN-SUFFIX,ir,DIRECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-domains.list,DIRECT
RULE-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-cidr.list,DIRECT
GEOIP,IR,DIRECT
FINAL,PROXY
```

به‌جای `PROXY` نام پراکسی یا policy group خود را بگذارید.

## Loon

این خطوط را در بخش `[Remote Rule]` اضافه کنید:

```
https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-injected.list, policy=REJECT, tag=ir-injected, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/malware.list, policy=REJECT, tag=malware, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/phishing.list, policy=REJECT, tag=phishing, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/cryptominers.list, policy=REJECT, tag=cryptominers, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/ads.list, policy=REJECT, tag=ads, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/sanctioned.list, policy=PROXY, tag=sanctioned, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-domains.list, policy=DIRECT, tag=ir-domains, enabled=true
https://github.com/aliraghebi/routing-rules/releases/latest/download/ir-cidr.list, policy=DIRECT, tag=ir-cidr, enabled=true
```

سپس `DOMAIN-SUFFIX,ir,DIRECT` و `GEOIP,IR,DIRECT` را در `[Rule]` اضافه کنید و `FINAL` را روی policy پراکسی
خود بگذارید. به‌جای `PROXY` نام policy group خود را بگذارید.

## فهرست‌های سبک‌تر

Surge می‌تواند فهرست‌های دامنه را به شکل `DOMAIN-SET` بارگیری کند که حافظه کمتری از `RULE-SET` مصرف می‌کند:

```
DOMAIN-SET,https://github.com/aliraghebi/routing-rules/releases/latest/download/ads-domainset.txt,REJECT
```

هر فهرست دامنه یک نسخه `-domainset.txt` دارد؛ ببینید [نشانی فایل‌ها](urls.md#surge-shadowrocket-domain-set).
`ads-lite.list` جایگزینی حدود ۵ هزار قانونی برای `ads.list` کامل است.
