// "Check a domain": evaluates a domain or IP against the published lists in
// the same order as the default configs. Lists are loaded from this site
// (dl/lists/), so there are no cross-origin requests.
(function () {
  "use strict";

  // Rule order of the default configs.
  var ORDER = [
    { list: "ir-injected", verdict: "block", why: "Iran's DNS block page address" },
    { list: "malware", verdict: "block" },
    { list: "phishing", verdict: "block" },
    { list: "cryptominers", verdict: "block" },
    { list: "ads", verdict: "block" },
    { list: "sanctioned", verdict: "proxy", why: "site that blocks Iranian IPs" },
    { tld: true, verdict: "direct", why: ".ir / .ایران domain" },
    { list: "ir-domains", verdict: "direct" },
    { list: "ir-cidr", verdict: "direct" },
  ];
  var OPTIONAL = ["tracking", "nsfw", "social", "arvancloud", "parspack", "derak", "cloudflare",
    "cloudfront", "fastly", "gcore", "telegram", "tor-exit", "netflix"];

  var cache = {};

  function load(name) {
    if (!cache[name]) {
      var url = new URL("../dl/lists/" + name + ".list", location.href);
      cache[name] = fetch(url).then(function (r) {
        if (!r.ok) throw new Error(name + ": HTTP " + r.status);
        return r.text();
      }).then(parse);
    }
    return cache[name];
  }

  function parse(text) {
    var l = { suffix: new Set(), exact: new Set(), keyword: [], cidr: [] };
    text.split("\n").forEach(function (line) {
      var f = line.trim().split(",");
      switch (f[0]) {
        case "DOMAIN-SUFFIX": l.suffix.add(f[1]); break;
        case "DOMAIN": l.exact.add(f[1]); break;
        case "DOMAIN-KEYWORD": l.keyword.push(f[1]); break;
        case "IP-CIDR": case "IP-CIDR6": var p = parsePrefix(f[1]); if (p) l.cidr.push(p); break;
      }
    });
    return l;
  }

  // --- IP helpers (BigInt) ---
  function parseIP(s) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      var n = 0n;
      var parts = s.split(".");
      for (var i = 0; i < 4; i++) {
        var o = Number(parts[i]);
        if (o > 255) return null;
        n = (n << 8n) | BigInt(o);
      }
      return { v6: false, n: n };
    }
    if (s.indexOf(":") >= 0) {
      var halves = s.split("::");
      if (halves.length > 2) return null;
      var head = halves[0] ? halves[0].split(":") : [];
      var tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
      var fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
      var groups = head.concat(Array(fill).fill("0"), tail);
      if (groups.length !== 8) return null;
      var v = 0n;
      for (var j = 0; j < 8; j++) {
        if (!/^[0-9a-f]{1,4}$/i.test(groups[j])) return null;
        v = (v << 16n) | BigInt(parseInt(groups[j], 16));
      }
      return { v6: true, n: v };
    }
    return null;
  }

  function parsePrefix(s) {
    var i = s.indexOf("/");
    var ip = parseIP(s.slice(0, i));
    if (!ip) return null;
    return { v6: ip.v6, n: ip.n, bits: Number(s.slice(i + 1)), text: s };
  }

  function inPrefix(ip, p) {
    if (ip.v6 !== p.v6) return false;
    var shift = BigInt((ip.v6 ? 128 : 32) - p.bits);
    return (ip.n >> shift) === (p.n >> shift);
  }

  // --- matching ---
  function matchDomain(l, host) {
    if (l.exact.has(host)) return "DOMAIN," + host;
    for (var h = host; ;) {
      if (l.suffix.has(h)) return "DOMAIN-SUFFIX," + h;
      var i = h.indexOf(".");
      if (i < 0) break;
      h = h.slice(i + 1);
    }
    for (var k = 0; k < l.keyword.length; k++) {
      if (host.indexOf(l.keyword[k]) >= 0) return "DOMAIN-KEYWORD," + l.keyword[k];
    }
    return null;
  }

  function matchIP(l, ip) {
    for (var i = 0; i < l.cidr.length; i++) {
      if (inPrefix(ip, l.cidr[i])) return (ip.v6 ? "IP-CIDR6," : "IP-CIDR,") + l.cidr[i].text;
    }
    return null;
  }

  function normalize(input) {
    var s = input.trim();
    if (!s) return null;
    var bare = s.replace(/^\[|\]$/g, "");
    var ip = parseIP(bare);
    if (ip) return { ip: ip, text: bare };
    try {
      var host = new URL(s.indexOf("://") >= 0 ? s : "http://" + s).hostname.replace(/\.$/, "");
      var ip2 = parseIP(host.replace(/^\[|\]$/g, ""));
      if (ip2) return { ip: ip2, text: host };
      // A hostname needs at least two labels of letters, digits, hyphens or underscores.
      if (!/^([a-z0-9_-]+\.)+[a-z0-9-]+$/.test(host)) return null;
      return { host: host, text: host };
    } catch (e) {
      return null;
    }
  }

  var LABEL = { block: "Blocked", proxy: "Through the proxy", direct: "Direct" };

  function check(input, out) {
    var q = normalize(input);
    if (!q) {
      out.innerHTML = '<p class="vr-check__error">Enter a domain, URL or IP address.</p>';
      return;
    }
    out.innerHTML = "<p>Checking <code>" + esc(q.text) + "</code>…</p>";
    var names = ORDER.filter(function (o) { return o.list; }).map(function (o) { return o.list; }).concat(OPTIONAL);
    Promise.all(names.map(function (n) {
      return load(n).then(function (l) { return [n, l]; }, function () { return [n, null]; });
    })).then(function (pairs) {
      var lists = {};
      pairs.forEach(function (p) { lists[p[0]] = p[1]; });
      var verdict = null;
      for (var i = 0; i < ORDER.length && !verdict; i++) {
        var o = ORDER[i];
        if (o.tld) {
          if (q.host && /(^|\.)(ir|xn--mgba3a4f16a)$/.test(q.host)) verdict = { o: o, rule: "DOMAIN-SUFFIX,ir" };
          continue;
        }
        var l = lists[o.list];
        if (!l) continue;
        var rule = q.host ? matchDomain(l, q.host) : matchIP(l, q.ip);
        if (rule) verdict = { o: o, rule: rule };
      }
      var optional = [];
      OPTIONAL.forEach(function (n) {
        var l = lists[n];
        var r = l && (q.host ? matchDomain(l, q.host) : matchIP(l, q.ip));
        if (r) optional.push("<li><code>" + n + "</code>: <code>" + esc(r) + "</code></li>");
      });
      var v = verdict ? verdict.o.verdict : "proxy";
      var html = '<div class="vr-check__verdict vr-check__verdict--' + v + '">' + LABEL[v] + "</div>";
      if (verdict) {
        html += "<p>Matched " + (verdict.o.list ? "<code>" + verdict.o.list + "</code>" : "the config rule") +
          (verdict.o.why ? " (" + verdict.o.why + ")" : "") + " by <code>" + esc(verdict.rule) + "</code>.</p>";
      } else {
        html += "<p>Not in any list, so the default rule sends it through the proxy.</p>";
        if (q.host) {
          html += "<p>Apps that resolve domains (Shadowrocket <code>GEOIP,IR</code>, Xray <code>IPIfNonMatch</code>, " +
            "mihomo <code>geoip-ir</code>) still send it direct if its IP address is Iranian. This page cannot resolve " +
            "DNS, so check the IP address too if you know it.</p>";
        }
      }
      if (optional.length) {
        html += "<p>Also in these optional lists (not used by the default configs):</p><ul>" + optional.join("") + "</ul>";
      }
      out.innerHTML = html;
    }).catch(function (e) {
      out.innerHTML = '<p class="vr-check__error">Could not load the lists: ' + esc(String(e)) + "</p>";
    });
  }

  function esc(s) {
    return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }

  function init() {
    var form = document.getElementById("vr-check-form");
    if (!form || form.dataset.ready) return;
    form.dataset.ready = "1";
    var input = document.getElementById("vr-check-input");
    var out = document.getElementById("vr-check-result");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      check(input.value, out);
    });
    var q = new URLSearchParams(location.search).get("q");
    if (q) {
      input.value = q;
      check(q, out);
    }
  }

  // Material's instant navigation swaps pages without reloading scripts.
  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
