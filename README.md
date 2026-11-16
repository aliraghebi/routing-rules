# vpn-routing

Routing rules for VPN/proxy clients in Iran, rebuilt daily by GitHub Actions from public upstream lists.
Inspired by [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules) and
[Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules).

- Blocks ads (including Iranian ad networks), malware, phishing and cryptominers.
- Proxies sites that refuse Iranian IPs.
- Sends Iranian domains and IP ranges direct; everything else goes through the proxy.

**Outputs:** Shadowrocket config and `RULE-SET` lists, sing-box rule-sets (`.srs` and JSON), and v2ray/Xray
`geosite.dat` / `geoip.dat`, served from GitHub and jsDelivr.

## Documentation

Setup guides for each client, every file URL, and the full source list:
**https://aliraghebi.github.io/vpn-routing/**

## How it works

`cmd/build` reads [`sources.yaml`](sources.yaml), then fetches, parses, normalizes and merges every source.
It runs safety checks (minimum sizes, shrink limits, allowlist, no blocking of Iranian sites) before writing
anything. Text outputs are committed to `dist/` on `main`. The full set, including the binaries, is published
to the `release` branch, which GitHub raw and jsDelivr serve.

```sh
go test ./...
go run ./cmd/build
```

To add a source, add an entry to `sources.yaml`; the format is documented at the top of that file.
[`allowlist.txt`](allowlist.txt) holds domains that must never be blocked, and [`ir-ads.txt`](ir-ads.txt)
holds Iranian ad networks to always block.

## License

The code is licensed under [GPL-3.0](LICENSE).

The generated lists are derived from third-party data and keep their upstream licenses. Some of those are
GPL-3.0 (hagezi, AdGuard) and AGPL-3.0 (PersianBlocker). Attribution:

- IP geolocation data: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0).
- Country IP blocks: [ipverse](https://github.com/ipverse/country-ip-blocks) (CC0), [ipdeny.com](https://www.ipdeny.com), [RIPEstat](https://stat.ripe.net).
- Domain lists: [bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains), [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community), and the other sources listed on the [sources page](https://aliraghebi.github.io/vpn-routing/sources).
