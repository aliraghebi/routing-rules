// Command build fetches all sources in sources.yaml and writes Shadowrocket
// rule lists, client configs and rule-sets into dist/, binary geo files into
// out/, and the generated docs pages into docs/.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aliraghebi/vpn-routing/internal/emit"
	"github.com/aliraghebi/vpn-routing/internal/fetch"
	"github.com/aliraghebi/vpn-routing/internal/merge"
	"github.com/aliraghebi/vpn-routing/internal/parse"
)

type Config struct {
	Settings struct {
		UserAgent   string        `yaml:"user_agent"`
		Timeout     time.Duration `yaml:"timeout"`
		Concurrency int           `yaml:"concurrency"`
		Retries     int           `yaml:"retries"`
		MaxBytes    int64         `yaml:"max_bytes"`
		ListCapWarn int           `yaml:"list_cap_warn"`
		RepoURL     string        `yaml:"repo_url"`
		BaseURL     string        `yaml:"base_url"`
	} `yaml:"settings"`
	Categories []Category `yaml:"categories"`
	Sources    []Source   `yaml:"sources"`
}

type Category struct {
	Name    string `yaml:"name"`
	Action  string `yaml:"action"` // reject | proxy | direct | none
	Enabled bool   `yaml:"enabled"`
}

type Source struct {
	Name        string            `yaml:"name"`
	URL         string            `yaml:"url"`
	Format      string            `yaml:"format"`
	Category    string            `yaml:"category"`
	Enabled     bool              `yaml:"enabled"`
	Match       string            `yaml:"match"`
	Filter      map[string]string `yaml:"filter"`
	Country     string            `yaml:"country"`
	MaxRules    int               `yaml:"max_rules"`
	MaxBytes    int64             `yaml:"max_bytes"`
	SkipInclude []string          `yaml:"skip_includes"`
	// OverrideDirect (REJECT sources only): this source's rules win over
	// ir-domains; matching ir-domains entries are dropped instead of the rule.
	OverrideDirect bool   `yaml:"override_direct"`
	License        string `yaml:"license"`
}

type outcome struct {
	src    Source
	res    parse.Result
	status string // ok | stale | skipped | FAILED
	err    error
}

// minBits rejects absurdly broad prefixes from any feed (a scraped 0.0.0.0/0
// in ir-cidr would send all traffic DIRECT).
var minBits = map[bool]int{true: 8, false: 16} // is4 -> min prefix length

func main() {
	cfgPath := flag.String("config", "sources.yaml", "source registry")
	dist := flag.String("dist", "dist", "output directory")
	cache := flag.String("cache", ".cache", "HTTP + last-known-good cache directory")
	allowPath := flag.String("allowlist", "allowlist.txt", "domains never to REJECT")
	out := flag.String("out", "out", "directory for binary release assets (geosite.dat, geoip.dat); not committed")
	docs := flag.String("docs", "docs", "GitHub Pages directory for the generated URL and sources pages")
	flag.Parse()
	log.SetFlags(0)
	if err := run(*cfgPath, *dist, *cache, *allowPath, *out, *docs); err != nil {
		log.Printf("::error::%v", err)
		os.Exit(1)
	}
}

func run(cfgPath, dist, cacheDir, allowPath, outDir, docsDir string) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("%s: %w", cfgPath, err)
	}
	cats := map[string]Category{}
	for _, c := range cfg.Categories {
		cats[c.Name] = c
	}
	for _, s := range cfg.Sources {
		if _, ok := cats[s.Category]; !ok {
			return fmt.Errorf("source %s: unknown category %q", s.Name, s.Category)
		}
		if parse.Formats[s.Format] == nil {
			return fmt.Errorf("source %s: unknown format %q", s.Name, s.Format)
		}
	}
	allow, err := readAllowlist(allowPath)
	if err != nil {
		return err
	}

	st := cfg.Settings
	f := &fetch.Fetcher{
		Client:   &http.Client{Timeout: st.Timeout, Transport: transport()},
		CacheDir: cacheDir,
		UA:       st.UserAgent,
		MaxBytes: st.MaxBytes,
		Retries:  st.Retries,
		Backoff:  2 * time.Second,
	}
	outcomes := fetchAll(f, cfg, cats, cacheDir)

	// Per-category merge.
	type built struct {
		cat     Category
		domains []parse.Domain
		cidrs   []netip.Prefix
		removed []string
		body    []byte
	}
	byCat := map[string]*built{}
	for _, c := range cfg.Categories {
		if c.Enabled {
			byCat[c.Name] = &built{cat: c}
		}
	}
	var stale []string
	var override []parse.Domain                  // all override_direct rules
	overrideByCat := map[string][]parse.Domain{} // same, per REJECT category
	for _, o := range outcomes {
		if o.src.OverrideDirect && byCat[o.src.Category] != nil && byCat[o.src.Category].cat.Action == "reject" {
			override = append(override, o.res.Domains...)
			overrideByCat[o.src.Category] = append(overrideByCat[o.src.Category], o.res.Domains...)
		}
		b := byCat[o.src.Category]
		if b == nil {
			continue
		}
		b.domains = append(b.domains, o.res.Domains...)
		b.cidrs = append(b.cidrs, o.res.CIDRs...)
		if o.status == "stale" {
			stale = append(stale, o.src.Name)
		}
	}
	for _, b := range byCat {
		b.domains = merge.Domains(b.domains)
		var broad []netip.Prefix
		b.cidrs = slices.DeleteFunc(merge.CIDRs(b.cidrs), func(p netip.Prefix) bool {
			if p.Bits() < minBits[p.Addr().Is4()] {
				broad = append(broad, p)
				return true
			}
			return false
		})
		for _, p := range broad {
			log.Printf("::warning::%s: dropped over-broad prefix %s", b.cat.Name, p)
		}
	}

	// Safety filters on REJECT lists.
	var protD []parse.Domain
	var protC []netip.Prefix
	if b := byCat["ir-domains"]; b != nil {
		protD = b.domains
		// ir-domains entries covered by a trusted Iran ad rule are ad networks,
		// not sites to send DIRECT. The conflict check still uses the full list.
		var rm []parse.Domain
		override, _ = merge.RemoveAllowed(override, allow) // allowlisted sites stay DIRECT
		b.domains, rm = merge.RemoveMatched(b.domains, override)
		for _, d := range rm {
			b.removed = append(b.removed, "override_direct "+ruleString(d))
		}
	}
	exempt := map[parse.Domain]bool{}
	for _, d := range override {
		exempt[d] = true
	}
	if b := byCat["ir-cidr"]; b != nil {
		protC = b.cidrs
	}
	var warns []string
	for _, b := range byCat {
		if b.cat.Action != "reject" {
			continue
		}
		var rm []parse.Domain
		b.domains, rm = merge.RemoveAllowed(b.domains, allow)
		for _, d := range rm {
			warns = append(warns, fmt.Sprintf("%s: allowlist blocked %s", b.cat.Name, ruleString(d)))
		}
		// Rules from override_direct sources skip the conflict check and are
		// re-added afterwards (the first merge may have folded them under a
		// broader generic rule that the check then removes).
		var rest []parse.Domain
		for _, d := range b.domains {
			if !exempt[d] {
				rest = append(rest, d)
			}
		}
		rest, rm = merge.RemoveConflicts(rest, protD)
		trusted, _ := merge.RemoveAllowed(overrideByCat[b.cat.Name], allow)
		b.domains = merge.Domains(append(trusted, rest...))
		for _, d := range rm {
			b.removed = append(b.removed, "ir-conflict "+ruleString(d))
		}
		var rmc []netip.Prefix
		b.cidrs, rmc = merge.RemoveCIDRConflicts(b.cidrs, protC)
		for _, p := range rmc {
			b.removed = append(b.removed, "ir-conflict "+p.String())
		}
	}
	slices.Sort(warns)
	for _, w := range warns {
		log.Printf("::warning::ALLOWLIST HIT — %s (removed from REJECT list)", w)
	}

	// Render. An enabled list with no rules means every source failed or a
	// parser broke; refuse to publish it. Big swings are allowed.
	var fatal []string
	for _, c := range cfg.Categories {
		b := byCat[c.Name]
		if b == nil {
			continue
		}
		b.body = emit.List(c.Name, b.domains, b.cidrs)
		n := len(b.domains) + len(b.cidrs)
		if n == 0 {
			fatal = append(fatal, c.Name+": list is empty")
		}
		if st.ListCapWarn > 0 && n > st.ListCapWarn {
			log.Printf("::warning::%s: %d rules exceeds list_cap_warn %d (iOS network extension memory)", c.Name, n, st.ListCapWarn)
		}
		for _, r := range b.removed {
			log.Printf("filtered: %s removed %s", c.Name, r)
		}
	}

	printSummary(outcomes, cfg.Categories, func(name string) (int, int, int) {
		b := byCat[name]
		if b == nil {
			return 0, 0, 0
		}
		return len(b.domains) + len(b.cidrs), len(b.body), len(b.removed)
	})
	if len(stale) > 0 {
		log.Printf("::warning::using last-known-good data for: %s", strings.Join(stale, ", "))
	}
	if len(fatal) > 0 {
		return fmt.Errorf("build refused, nothing written:\n  %s", strings.Join(fatal, "\n  "))
	}

	// Render every output into one map, then make dist/ match it exactly
	// (stale files from disabled categories are removed).
	if st.BaseURL == "" {
		return errors.New("settings.base_url must be set")
	}
	base := strings.TrimRight(st.BaseURL, "/")
	files := map[string][]byte{}
	for _, c := range cfg.Categories {
		if b := byCat[c.Name]; b != nil {
			files[c.Name+".list"] = b.body
		}
	}
	sets := map[string]catRules{}
	for name, b := range byCat {
		sets[name] = catRules{b.cat, b.domains, b.cidrs}
	}
	g := buildGeo(cfg.Categories, sets)
	for _, t := range g.sites {
		b, err := emit.SingBoxDomains(t.Domains)
		if err != nil {
			return err
		}
		files["geosite-"+t.Name+".json"] = b
	}
	for _, t := range g.ips {
		b, err := emit.SingBoxCIDRs(t.CIDRs)
		if err != nil {
			return err
		}
		files["geoip-"+t.Name+".json"] = b
	}
	xr, err := emit.XrayRouting(g.route)
	if err != nil {
		return err
	}
	files["xray-routing.json"] = xr
	vn, err := emit.V2rayNRouting(g.route)
	if err != nil {
		return err
	}
	files["v2rayn-routing.json"] = vn
	// Files that embed rule-set URLs.
	cd := confData(cfg.Categories, byCat)
	cd.Repo, cd.BaseURL, cd.Self = st.RepoURL, base, "shadowrocket.conf"
	conf, err := emit.Conf(cd)
	if err != nil {
		return err
	}
	files[cd.Self] = conf
	rd := g.route
	rd.BaseURL = base
	route, err := emit.SingBoxRoute(rd)
	if err != nil {
		return err
	}
	files["sing-box-route.json"] = route
	// Karing has no PROXY group here: unmatched traffic already uses the selected proxy.
	karing, err := emit.Karing(base, g.route.Reject, append(slices.Clone(g.route.Direct), "geoip-private"))
	if err != nil {
		return err
	}
	files["karing.json"] = karing
	clashRoute := g.route
	clashRoute.All = append(slices.Clone(g.route.All), "geoip-private")
	files["clash.yaml"] = emit.ClashConfig(base, clashRoute)

	// DNS blocks for the cores (merge with the matching route/rules file).
	files["sing-box-dns.json"] = emit.SingBoxDNS()
	files["xray-dns.json"] = emit.XrayDNS()
	files["clash-dns.yaml"] = emit.ClashDNS()

	// Networks: WireGuard split tunnel, routers, ipset/nftables.
	if ir := byCat["ir-cidr"]; ir != nil {
		files["wireguard-allowedips.txt"] = emit.WireGuardAllowedIPs(merge.Complement(append(slices.Clone(ir.cidrs), emit.Private...)))
		// Lite: IPv4 only, excluding Iranian blocks of /20 or larger (~1.7k entries,
		// ~90% of Iranian IPv4 space still direct), all IPv6 through the tunnel.
		// ponytail: fixed /20 cut-off; make it configurable if mobile clients need fewer entries.
		var big []netip.Prefix
		for _, p := range ir.cidrs {
			if p.Addr().Is4() && p.Bits() <= 20 {
				big = append(big, p)
			}
		}
		var lite []netip.Prefix
		for _, p := range merge.Complement(append(big, emit.Private...)) {
			if p.Addr().Is4() {
				lite = append(lite, p)
			}
		}
		files["wireguard-allowedips-lite.txt"] = emit.WireGuardAllowedIPs(append(lite, netip.MustParsePrefix("::/0")))
		files["openvpn-ir-routes.txt"] = emit.OpenVPN(ir.cidrs)
		files["openvpn-ir-routes-lite.txt"] = emit.OpenVPN(big) // same /20 cut-off as the WireGuard lite file
		files["mikrotik-ir.rsc"] = emit.MikroTik("IR", ir.cidrs)
		files["ir-cidr4.txt"] = emit.CIDRLines(ir.cidrs, true)
		files["ir-cidr6.txt"] = emit.CIDRLines(ir.cidrs, false)
	}
	// Browsers: PAC with Iranian domains (including the TLDs) direct.
	for _, t := range g.sites {
		if t.Name == "ir" {
			files["proxy.pac"] = emit.PAC(t.Domains)
		}
	}
	// Surge/Shadowrocket DOMAIN-SET, AdGuard Home / Pi-hole blocklists.
	var defaultBlock []parse.Domain
	for _, c := range cfg.Categories {
		b := byCat[c.Name]
		if b == nil || len(b.domains) == 0 {
			continue
		}
		files[c.Name+"-domainset.txt"] = emit.DomainSet(b.domains)
		if c.Action == "reject" || dnsBlocklist[c.Name] {
			files["adguard-"+c.Name+".txt"] = emit.AdGuard(c.Name, b.domains)
		}
		if c.Action == "reject" {
			defaultBlock = append(defaultBlock, b.domains...)
		}
	}
	defaultBlock = merge.Domains(defaultBlock)
	files["adguard-default.txt"] = emit.AdGuard("default (malware, phishing, cryptominers, ads)", defaultBlock)
	files["hosts-default.txt"] = emit.Hosts("default (malware, phishing, cryptominers, ads)", defaultBlock)
	if err := syncDir(dist, files); err != nil {
		return err
	}

	// Binary outputs, published as release assets by CI.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(outDir, "geosite.dat"), emit.GeoSiteDat(g.sites)); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(outDir, "geoip.dat"), emit.GeoIPDat(g.ips)); err != nil {
		return err
	}
	// mihomo text rule-sets; CI compiles them to .mrs with the official binary.
	clash := map[string][]byte{}
	for _, t := range g.sites {
		b, skipped := emit.ClashDomainText(t.Domains)
		if skipped > 0 {
			log.Printf("::warning::geosite-%s: %d DOMAIN-KEYWORD rules skipped for mihomo (domain behavior has no keyword type)", t.Name, skipped)
		}
		if len(b) > 0 {
			clash["geosite-"+t.Name+".txt"] = b
		}
	}
	for _, t := range g.ips {
		clash["geoip-"+t.Name+".txt"] = emit.ClashIPText(t.CIDRs)
	}
	if err := syncDir(filepath.Join(outDir, "clash"), clash); err != nil {
		return err
	}
	return writeDocs(docsDir, cfg, g, files)
}

// dnsBlocklist marks optional categories that also make sense as DNS blocklists.
var dnsBlocklist = map[string]bool{"ads-lite": true, "tracking": true, "nsfw": true, "social": true}

type catRules struct {
	cat     Category
	domains []parse.Domain
	cidrs   []netip.Prefix
}

type geo struct {
	sites, ips []emit.Tag
	route      emit.RouteData // BaseURL is filled in by the caller
}

// geoTag maps a category to its v2ray/sing-box tag (Chocolate4U naming).
func geoTag(cat string) string {
	switch cat {
	case "ir-domains", "ir-cidr":
		return "ir"
	case "tor-exit":
		return "tor"
	}
	return cat
}

// buildGeo derives v2ray/sing-box tags and the routing template data.
func buildGeo(cats []Category, sets map[string]catRules) geo {
	var g geo
	rd := &g.route
	for _, c := range cats {
		r, ok := sets[c.Name]
		if !ok {
			continue
		}
		tag := geoTag(c.Name)
		if len(r.domains) > 0 {
			d := r.domains
			if tag == "ir" { // the Shadowrocket config adds these TLDs inline instead
				d = merge.Domains(append(slices.Clone(d), parse.Domain{Kind: parse.Suffix, Name: "ir"}, parse.Domain{Kind: parse.Suffix, Name: "xn--mgba3a4f16a"}))
			}
			g.sites = append(g.sites, emit.Tag{Name: tag, Domains: d})
			switch c.Action {
			case "reject":
				rd.Reject = append(rd.Reject, "geosite-"+tag)
				rd.RejectSite = append(rd.RejectSite, tag)
			case "proxy":
				rd.Proxy = append(rd.Proxy, "geosite-"+tag)
				rd.ProxySite = append(rd.ProxySite, tag)
			case "direct":
				rd.Direct = append(rd.Direct, "geosite-"+tag)
			}
		}
		if len(r.cidrs) > 0 {
			g.ips = append(g.ips, emit.Tag{Name: tag, CIDRs: r.cidrs})
			if c.Name == "ir-injected" {
				rd.Early = append(rd.Early, "geoip-"+tag)
				rd.EarlyIP = append(rd.EarlyIP, tag)
			}
			switch c.Action {
			case "reject":
				rd.Reject = append(rd.Reject, "geoip-"+tag)
				rd.RejectIP = append(rd.RejectIP, tag)
			case "proxy":
				rd.Proxy = append(rd.Proxy, "geoip-"+tag)
			case "direct":
				rd.Direct = append(rd.Direct, "geoip-"+tag)
			}
		}
	}
	// The route only declares the rule-sets its rules reference.
	rd.All = slices.Concat(rd.Reject, rd.Proxy, rd.Direct)
	g.ips = append(g.ips, emit.Tag{Name: "private", CIDRs: emit.Private})
	byName := func(a, b emit.Tag) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(g.sites, byName)
	slices.SortFunc(g.ips, byName)
	return g
}

// writeDocs generates the URL and sources pages for the GitHub Pages site.
func writeDocs(dir string, cfg Config, g geo, files map[string][]byte) error {
	st := cfg.Settings
	row := func(name, desc string) emit.DocRow {
		return emit.DocRow{Name: name, Desc: desc, URL: strings.TrimRight(st.BaseURL, "/") + "/" + name}
	}
	var sr, lists, sb, sbSrc, v2 emit.DocSection
	sr = emit.DocSection{Title: "Shadowrocket config", Note: "Import this URL in Shadowrocket."}
	sr.Rows = append(sr.Rows, row("shadowrocket.conf", "Full config: REJECT, PROXY, DIRECT, GEOIP, FINAL"))
	lists = emit.DocSection{Title: "Shadowrocket rule lists", Note: "`RULE-SET` text lists in Shadowrocket (Surge-style) syntax."}
	for _, c := range cfg.Categories {
		if _, ok := files[c.Name+".list"]; ok {
			lists.Rows = append(lists.Rows, row(c.Name+".list", fmt.Sprintf("%s (%s)", c.Name, actionDesc(c.Action))))
		}
	}
	sb = emit.DocSection{Title: "sing-box rule-sets (binary)", Note: "Use with `\"type\": \"remote\", \"format\": \"binary\"`. Rule-set format version 1, readable by sing-box 1.8+ and apps built on it."}
	sbSrc = emit.DocSection{Title: "sing-box rule-sets (JSON source)", Note: "Same rules as JSON, for `\"format\": \"source\"`."}
	sb.Rows = append(sb.Rows, row("sing-box-route.json", "Example `route` block (sing-box 1.11+)"))
	for _, t := range g.sites {
		sb.Rows = append(sb.Rows, row("geosite-"+t.Name+".srs", "domains: "+t.Name))
		sbSrc.Rows = append(sbSrc.Rows, row("geosite-"+t.Name+".json", "domains: "+t.Name))
	}
	for _, t := range g.ips {
		sb.Rows = append(sb.Rows, row("geoip-"+t.Name+".srs", "IP ranges: "+t.Name))
		sbSrc.Rows = append(sbSrc.Rows, row("geoip-"+t.Name+".json", "IP ranges: "+t.Name))
	}
	apps := emit.DocSection{Title: "App configs", Note: "Ready-made rule files for apps with their own format."}
	apps.Rows = append(apps.Rows,
		row("karing.json", "Karing custom diversion rules (Block, Direct)"),
		row("v2rayn-routing.json", "v2rayN / v2rayNG custom routing rules (needs this project's geo files)"))
	cl := emit.DocSection{Title: "Clash / mihomo rule-sets", Note: "`.mrs` rule-sets for mihomo (`format: mrs`; `behavior: domain` for geosite, `ipcidr` for geoip)."}
	cl.Rows = append(cl.Rows, row("clash.yaml", "`rule-providers` and `rules` to merge into a mihomo config (needs a `PROXY` group)"))
	for _, t := range g.sites {
		cl.Rows = append(cl.Rows, row("geosite-"+t.Name+".mrs", "domains: "+t.Name))
	}
	for _, t := range g.ips {
		cl.Rows = append(cl.Rows, row("geoip-"+t.Name+".mrs", "IP ranges: "+t.Name))
	}
	dns := emit.DocSection{Title: "DNS", Note: "DNS blocks to merge into a config: Iranian domains use the device's DNS, everything else DNS-over-HTTPS through the proxy."}
	dns.Rows = append(dns.Rows,
		row("sing-box-dns.json", "sing-box `dns` block (1.12+), merge with `sing-box-route.json`"),
		row("xray-dns.json", "Xray `dns` block, merge with `xray-routing.json`"),
		row("clash-dns.yaml", "mihomo `dns` block (fake-ip), merge with `clash.yaml`"))
	net := emit.DocSection{Title: "Networks and routers", Note: "Iran IP ranges for split tunneling outside proxy apps."}
	net.Rows = append(net.Rows,
		row("wireguard-allowedips.txt", "WireGuard `AllowedIPs`: everything except Iran and private ranges (~16k entries, desktop)"),
		row("wireguard-allowedips-lite.txt", "Same, IPv4 only, larger Iranian blocks only (~1.7k entries, phones); all IPv6 through the tunnel"),
		row("openvpn-ir-routes.txt", "OpenVPN client routes that keep Iranian IPv4 ranges outside the tunnel"),
		row("openvpn-ir-routes-lite.txt", "Same, larger Iranian blocks only (fewer routes, for phones)"),
		row("mikrotik-ir.rsc", "MikroTik RouterOS script: address list `IR`"),
		row("ir-cidr4.txt", "Iran IPv4 ranges, one per line (ipset, nftables)"),
		row("ir-cidr6.txt", "Iran IPv6 ranges, one per line"),
		row("proxy.pac", "Browser PAC: Iranian domains direct, everything else through a local proxy"))
	dnsf := emit.DocSection{Title: "AdGuard Home and Pi-hole", Note: "DNS blocklists. `adguard-*` work in AdGuard Home and Pi-hole v6; `hosts-*` in Pi-hole v5 and hosts files."}
	dnsf.Rows = append(dnsf.Rows,
		row("adguard-default.txt", "Everything the default configs block (malware, phishing, cryptominers, ads)"),
		row("hosts-default.txt", "Same, hosts format (subdomains not blocked)"))
	ds := emit.DocSection{Title: "Surge / Shadowrocket DOMAIN-SET", Note: "Domain-only lists in DOMAIN-SET format, lighter than the same rules as RULE-SET."}
	for _, c := range cfg.Categories {
		if _, ok := files["adguard-"+c.Name+".txt"]; ok {
			dnsf.Rows = append(dnsf.Rows, row("adguard-"+c.Name+".txt", c.Name))
		}
		if _, ok := files[c.Name+"-domainset.txt"]; ok {
			ds.Rows = append(ds.Rows, row(c.Name+"-domainset.txt", c.Name))
		}
	}
	v2 = emit.DocSection{Title: "v2ray / Xray", Note: "Tags: `geosite:<name>` and `geoip:<name>` as listed in the sing-box tables above."}
	v2.Rows = append(v2.Rows,
		row("geosite.dat", "Domain tags"),
		row("geoip.dat", "IP tags, including `private`"),
		row("xray-routing.json", "Example `routing` block"))

	urls, err := emit.URLsPage(emit.URLDocs{RepoURL: st.RepoURL, BaseURL: strings.TrimRight(st.BaseURL, "/"), Sections: []emit.DocSection{sr, lists, ds, apps, sb, sbSrc, cl, v2, dns, net, dnsf}})
	if err != nil {
		return err
	}
	var srcs []emit.DocSource
	for _, s := range cfg.Sources {
		srcs = append(srcs, emit.DocSource{Name: s.Name, URL: s.URL, Category: s.Category, Format: s.Format, License: s.License, Enabled: s.Enabled && catEnabled(cfg, s.Category)})
	}
	sources, err := emit.SourcesPage(srcs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(dir, "urls.md"), urls); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(dir, "sources.md"), sources); err != nil {
		return err
	}
	// Copies of the files users import as files, served by the docs site itself:
	// a same-origin link with the download attribute makes browsers save the file
	// instead of showing it as text (release-asset links force a download, but go through github.com redirects).
	dl := map[string][]byte{}
	for name, b := range files {
		for _, stem := range []string{"karing", "v2rayn-routing", "clash", "sing-box-route", "sing-box-dns", "xray-routing", "xray-dns",
			"shadowrocket", "proxy.pac", "mikrotik-ir", "wireguard-allowedips", "openvpn-ir-routes"} {
			if strings.HasPrefix(name, stem) {
				dl[name] = b
			}
		}
	}
	if err := syncDir(filepath.Join(dir, "dl"), dl); err != nil {
		return err
	}
	// Lists the "Check a domain" page loads (same origin, so no CORS issues).
	checkLists := map[string][]byte{}
	for _, c := range cfg.Categories {
		if b, ok := files[c.Name+".list"]; ok && c.Name != "ads-lite" {
			checkLists[c.Name+".list"] = b
		}
	}
	return syncDir(filepath.Join(dir, "dl", "lists"), checkLists)
}

func actionDesc(a string) string {
	switch a {
	case "reject":
		return "REJECT"
	case "proxy":
		return "PROXY"
	case "direct":
		return "DIRECT"
	}
	return "optional, not in the config"
}

func catEnabled(cfg Config, name string) bool {
	for _, c := range cfg.Categories {
		if c.Name == name {
			return c.Enabled
		}
	}
	return false
}

// syncDir makes dir contain exactly the given files (stale files are removed;
// subdirectories are left alone).
func syncDir(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if _, ok := files[e.Name()]; !ok && !e.IsDir() {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	for name, b := range files {
		if err := writeIfChanged(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	return nil
}

func confData[T any](cats []Category, on map[string]T) emit.ConfData {
	d := emit.ConfData{On: map[string]bool{}}
	for _, c := range cats {
		if _, ok := on[c.Name]; !ok {
			continue
		}
		switch c.Name {
		case "sanctioned":
			d.On["sanctioned"] = true
		case "ir-domains":
			d.On["irdomains"] = true
		case "ir-cidr":
			d.On["ircidr"] = true
		default:
			if c.Action == "reject" {
				d.Reject = append(d.Reject, c.Name)
			}
		}
	}
	return d
}

func fetchAll(f *fetch.Fetcher, cfg Config, cats map[string]Category, cacheDir string) []outcome {
	out := make([]outcome, len(cfg.Sources))
	sem := make(chan struct{}, max(1, cfg.Settings.Concurrency))
	var wg sync.WaitGroup
	for i, s := range cfg.Sources {
		out[i].src = s
		if !s.Enabled || !cats[s.Category].Enabled {
			out[i].status = "disabled"
			continue
		}
		wg.Add(1)
		go func(o *outcome) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := fetchOne(f, o.src)
			lkg := filepath.Join(cacheDir, "sources", o.src.Name+".json")
			if err == nil && len(res.Domains)+len(res.CIDRs) == 0 {
				err = errors.New("parsed zero rules")
			}
			if err == nil {
				o.res, o.status = res, "ok"
				if werr := saveLKG(lkg, res); werr != nil {
					log.Printf("::warning::%s: saving last-known-good: %v", o.src.Name, werr)
				}
				return
			}
			o.err = err
			if res, lerr := loadLKG(lkg); lerr == nil {
				o.res, o.status = res, "stale"
				log.Printf("::warning::%s: %v; using last-known-good", o.src.Name, err)
			} else {
				o.status = "FAILED"
				log.Printf("::warning::%s: %v; no last-known-good available", o.src.Name, err)
			}
		}(&out[i])
	}
	wg.Wait()
	return out
}

// transport adds file:// support so sources can point at files in this repo
// (file:///ir-ads.txt resolves relative to the working directory).
func transport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir(".")))
	return t
}

// monthPlaceholder in a source URL is replaced by the current UTC month
// ("2026-11"), falling back to the previous month while the new file is not
// published yet (DB-IP names its monthly dumps this way).
const monthPlaceholder = "{YYYY-MM}"

func getMonthly(ctx context.Context, f *fetch.Fetcher, url string, maxBytes int64) ([]byte, error) {
	if !strings.Contains(url, monthPlaceholder) {
		return f.Get(ctx, url, maxBytes)
	}
	now := time.Now().UTC()
	b, err := f.Get(ctx, strings.ReplaceAll(url, monthPlaceholder, now.Format("2006-01")), maxBytes)
	if err == nil {
		return b, nil
	}
	prev := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.UTC)
	if b, perr := f.Get(ctx, strings.ReplaceAll(url, monthPlaceholder, prev.Format("2006-01")), maxBytes); perr == nil {
		return b, nil
	}
	return nil, err
}

func fetchOne(f *fetch.Fetcher, s Source) (parse.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	url := s.URL
	body, err := getMonthly(ctx, f, url, s.MaxBytes)
	if err != nil {
		return parse.Result{}, err
	}
	opt := parse.Options{Match: parse.Exact, Filter: s.Filter, Country: s.Country}
	if s.Match == "suffix" {
		opt.Match = parse.Suffix
	}
	if s.Format == "v2fly" {
		base := url[:strings.LastIndexByte(url, '/')+1]
		opt.Include = func(name string) ([]byte, error) {
			if slices.Contains(s.SkipInclude, name) {
				return nil, nil
			}
			return f.Get(ctx, base+name, s.MaxBytes)
		}
	}
	res, err := parse.Formats[s.Format](body, opt)
	if err != nil {
		return parse.Result{}, err
	}
	if s.MaxRules > 0 {
		res = truncate(res, s.MaxRules)
	}
	return res, nil
}

// truncate keeps the first n unique rules in upstream order (upstream lists
// are often ranked, so the head is the most valuable part).
func truncate(r parse.Result, n int) parse.Result {
	var out parse.Result
	seenD := map[parse.Domain]bool{}
	for _, d := range r.Domains {
		if len(out.Domains) >= n {
			break
		}
		if !seenD[d] {
			seenD[d] = true
			out.Domains = append(out.Domains, d)
		}
	}
	seenC := map[netip.Prefix]bool{}
	for _, p := range r.CIDRs {
		if len(out.Domains)+len(out.CIDRs) >= n {
			break
		}
		if !seenC[p] {
			seenC[p] = true
			out.CIDRs = append(out.CIDRs, p)
		}
	}
	return out
}

type lkgFile struct {
	Domains []string `json:"domains"`
	CIDRs   []string `json:"cidrs"`
}

func saveLKG(path string, r parse.Result) error {
	var l lkgFile
	for _, d := range r.Domains {
		l.Domains = append(l.Domains, ruleString(d))
	}
	for _, p := range r.CIDRs {
		l.CIDRs = append(l.CIDRs, p.String())
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadLKG(path string) (parse.Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return parse.Result{}, err
	}
	var l lkgFile
	if err := json.Unmarshal(b, &l); err != nil {
		return parse.Result{}, err
	}
	var r parse.Result
	kinds := map[string]parse.Kind{"DOMAIN-SUFFIX": parse.Suffix, "DOMAIN": parse.Exact, "DOMAIN-KEYWORD": parse.Keyword}
	for _, s := range l.Domains {
		k, n, _ := strings.Cut(s, ",")
		if kind, ok := kinds[k]; ok {
			r.Domains = append(r.Domains, parse.Domain{Kind: kind, Name: n})
		}
	}
	for _, s := range l.CIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			r.CIDRs = append(r.CIDRs, p)
		}
	}
	if len(r.Domains)+len(r.CIDRs) == 0 {
		return r, errors.New("empty last-known-good")
	}
	return r, nil
}

func ruleString(d parse.Domain) string {
	return [...]string{"DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD"}[d.Kind] + "," + d.Name
}

func readAllowlist(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l, _, _ := strings.Cut(sc.Text(), "#")
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		d, ok := parse.NormalizeDomain(l)
		if !ok {
			return nil, fmt.Errorf("%s: invalid domain %q", path, l)
		}
		out = append(out, d)
	}
	return out, sc.Err()
}

func writeIfChanged(path string, b []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return nil
	}
	return os.WriteFile(path, b, 0o644)
}

func printSummary(outs []outcome, cats []Category, stat func(string) (n, size, conflicts int)) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "SOURCE\tCATEGORY\tSTATUS\tDOMAINS\tCIDRS\tNOTE\t")
	for _, o := range outs {
		note := ""
		if o.err != nil {
			note = o.err.Error()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t\n", o.src.Name, o.src.Category, o.status, len(o.res.Domains), len(o.res.CIDRs), note)
	}
	w.Flush()
	fmt.Println()
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "LIST\tACTION\tRULES\tSIZE KB\tIR-CONFLICTS\t")
	for _, c := range cats {
		n, size, conf := stat(c.Name)
		if !c.Enabled {
			fmt.Fprintf(w, "%s\t%s\tdisabled\t\t\t\n", c.Name, c.Action)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%.1f\t%d\t\n", c.Name, c.Action, n, float64(size)/1024, conf)
	}
	w.Flush()
}
