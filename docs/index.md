# vpn-routing

Routing rules for VPN/proxy clients in Iran, rebuilt every day from public upstream lists:

- **Block** ads (including Iranian ad networks), malware, phishing and cryptominers.
- **Proxy** sites that refuse Iranian IPs (sanctioned).
- **Send Iranian sites and IP ranges direct**, so domestic services stay fast and don't see a foreign IP.
- **Proxy everything else.**

## Pick your client

| Client | Guide |
|--------|-------|
| Shadowrocket (iOS) | [Shadowrocket guide](shadowrocket.md) |
| sing-box, and apps built on it (SFI, SFA, Hiddify, Karing, NekoBox…) | [sing-box guide](sing-box.md) |
| v2ray / Xray, v2rayN, v2rayNG, and other Xray-based apps | [v2ray / Xray guide](v2ray.md) |

Every file and its URL: [File URLs](urls.md). Where the data comes from: [Sources and licenses](sources.md).

## GitHub or jsDelivr?

Every file is published on two mirrors with the same file names:

| Mirror | Base URL | Notes |
|--------|----------|-------|
| GitHub | `https://raw.githubusercontent.com/aliraghebi/vpn-routing/release` | Updated within minutes. Often filtered in Iran. |
| jsDelivr | `https://cdn.jsdelivr.net/gh/aliraghebi/vpn-routing@release` | CDN, usually reachable. The build purges the cache after each update, but a stale copy can still be served for a while. |

If neither works, `fastly.jsdelivr.net` and `gcore.jsdelivr.net` serve the same paths as `cdn.jsdelivr.net`.
Avoid untrusted "GitHub proxy" sites: they can change the files, and these files decide what goes through
your VPN and what goes direct.

## What the rules do, in order

1. Malware, phishing, cryptominer and ad domains/IPs → **block**
2. Sanctioned sites (that block Iranian IPs) → **proxy**
3. `.ir` domains and Iranian sites → **direct**
4. Iranian IP ranges → **direct**
5. Everything else → **proxy**

Optional lists that are not in the default configs: social media, adult content, and IP ranges for
Cloudflare, CloudFront, Fastly, G-Core, Telegram, Tor exit nodes and Netflix.
