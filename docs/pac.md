---
icon: material/web
---

# Browsers (PAC)

A proxy auto-config (PAC) file tells a browser which sites to send through a proxy. `proxy.pac` sends
Iranian domains (including all `.ir` domains) direct and everything else through your VPN client's local
proxy.

[:material-download: Download proxy.pac](dl/proxy.pac){ .md-button .md-button--primary download="proxy.pac" }

If the button doesn't work, download it from [GitHub Releases](https://github.com/aliraghebi/vpn-routing/releases/latest/download/proxy.pac).

## Set the proxy address

Open the file and set the first line to your client's local proxy:

```js
var PROXY = "SOCKS5 127.0.0.1:10808; SOCKS 127.0.0.1:10808";
```

The defaults match v2rayN (SOCKS on `10808`; HTTP is `10809`, written as `PROXY 127.0.0.1:10809`).

!!! note "No direct fallback"
    The file deliberately has no `DIRECT` fallback. If your VPN client stops, sites fail to load instead of
    silently opening without protection.

## Use it

- **SwitchyOmega / ZeroOmega**: new profile → **PAC Profile** → paste the file's content.
- **Firefox**: Settings → Network Settings → **Automatic proxy configuration URL** → a `file://` path to the
  saved file.
- **Windows / macOS system proxy**: set the automatic configuration (PAC) to the saved file.

A PAC file can't block ads, and it only matches domain names: Iranian sites opened by IP address go through
the proxy.
