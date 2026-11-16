// Command build fetches all sources in sources.yaml and writes Shadowrocket
// rule lists plus shadowrocket.conf into dist/.
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
		MaxShrink   float64       `yaml:"max_shrink"`
		ListCapWarn int           `yaml:"list_cap_warn"`
		BaseURL     string        `yaml:"base_url"`
		RepoURL     string        `yaml:"repo_url"`
	} `yaml:"settings"`
	Categories []Category `yaml:"categories"`
	Sources    []Source   `yaml:"sources"`
}

type Category struct {
	Name     string `yaml:"name"`
	Action   string `yaml:"action"` // reject | proxy | direct | none
	Enabled  bool   `yaml:"enabled"`
	MinRules int    `yaml:"min_rules"`
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
	RequiresEnv []string          `yaml:"requires_env"`
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
	flag.Parse()
	log.SetFlags(0)
	if err := run(*cfgPath, *dist, *cache, *allowPath, *out); err != nil {
		log.Printf("::error::%v", err)
		os.Exit(1)
	}
}

func run(cfgPath, dist, cacheDir, allowPath, outDir string) error {
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
		cat      Category
		domains  []parse.Domain
		cidrs    []netip.Prefix
		removed  []string
		body     []byte
		oldRules int
		oldExist bool
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

	// Render and check thresholds.
	var fatal []string
	allowShrink := os.Getenv("ALLOW_SHRINK") == "1"
	for _, c := range cfg.Categories {
		b := byCat[c.Name]
		if b == nil {
			continue
		}
		b.body = emit.List(c.Name, b.domains, b.cidrs)
		n := len(b.domains) + len(b.cidrs)
		if old, err := os.ReadFile(filepath.Join(dist, c.Name+".list")); err == nil {
			b.oldRules, b.oldExist = emit.CountRules(old), true
		}
		if n < c.MinRules {
			fatal = append(fatal, fmt.Sprintf("%s: %d rules < min_rules %d", c.Name, n, c.MinRules))
		}
		if b.oldExist && b.oldRules > 0 && float64(n) < float64(b.oldRules)*(1-st.MaxShrink) {
			msg := fmt.Sprintf("%s: shrank %d -> %d (more than %.0f%%)", c.Name, b.oldRules, n, st.MaxShrink*100)
			if allowShrink {
				log.Printf("::warning::%s (ALLOW_SHRINK=1)", msg)
			} else {
				fatal = append(fatal, msg+"; rerun with ALLOW_SHRINK=1 if intended")
			}
		}
		if st.ListCapWarn > 0 && n > st.ListCapWarn {
			log.Printf("::warning::%s: %d rules exceeds list_cap_warn %d (iOS network extension memory)", c.Name, n, st.ListCapWarn)
		}
		for _, r := range b.removed {
			log.Printf("filtered: %s removed %s", c.Name, r)
		}
	}

	printSummary(outcomes, cfg.Categories, func(name string) (int, int, int, bool, int) {
		b := byCat[name]
		if b == nil {
			return 0, 0, 0, false, 0
		}
		return len(b.domains) + len(b.cidrs), len(b.body), b.oldRules, b.oldExist, len(b.removed)
	})
	if len(stale) > 0 {
		log.Printf("::warning::using last-known-good data for: %s", strings.Join(stale, ", "))
	}
	if len(fatal) > 0 {
		return fmt.Errorf("build refused, dist/ left untouched:\n  %s", strings.Join(fatal, "\n  "))
	}

	// Write outputs.
	if err := os.MkdirAll(dist, 0o755); err != nil {
		return err
	}
	for _, c := range cfg.Categories {
		path := filepath.Join(dist, c.Name+".list")
		if b := byCat[c.Name]; b != nil {
			if err := writeIfChanged(path, b.body); err != nil {
				return err
			}
		} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if st.BaseURL == "" && os.Getenv("BASE_URL") == "" {
		return errors.New("settings.base_url or BASE_URL must be set")
	}
	conf, err := emit.Conf(confData(st.BaseURL, st.RepoURL, cfg.Categories, byCat))
	if err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(dist, "shadowrocket.conf"), conf); err != nil {
		return err
	}
	sets := map[string]catRules{}
	for name, b := range byCat {
		sets[name] = catRules{b.cat, b.domains, b.cidrs}
	}
	return writeGeo(cfg.Categories, sets, dist, outDir, strings.TrimRight(st.RepoURL, "/")+"/releases/latest/download")
}

type catRules struct {
	cat     Category
	domains []parse.Domain
	cidrs   []netip.Prefix
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

// writeGeo emits v2ray geosite.dat/geoip.dat into outDir (release assets) and
// sing-box source rule-sets plus example routing configs into dist/.
func writeGeo(cats []Category, sets map[string]catRules, dist, outDir, releaseURL string) error {
	var sites, ips []emit.Tag
	var rd emit.RouteData
	rd.ReleaseURL = releaseURL
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
			sites = append(sites, emit.Tag{Name: tag, Domains: d})
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
			ips = append(ips, emit.Tag{Name: tag, CIDRs: r.cidrs})
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
	// route.json only declares the rule-sets its rules reference.
	rd.All = slices.Concat(rd.Reject, rd.Proxy, rd.Direct)
	ips = append(ips, emit.Tag{Name: "private", CIDRs: emit.Private})
	byName := func(a, b emit.Tag) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(sites, byName)
	slices.SortFunc(ips, byName)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(outDir, "geosite.dat"), emit.GeoSiteDat(sites)); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(outDir, "geoip.dat"), emit.GeoIPDat(ips)); err != nil {
		return err
	}

	sbDir := filepath.Join(dist, "sing-box")
	want := map[string][]byte{}
	for _, t := range sites {
		b, err := emit.SingBoxDomains(t.Domains)
		if err != nil {
			return err
		}
		want["geosite-"+t.Name+".json"] = b
	}
	for _, t := range ips {
		b, err := emit.SingBoxCIDRs(t.CIDRs)
		if err != nil {
			return err
		}
		want["geoip-"+t.Name+".json"] = b
	}
	route, err := emit.SingBoxRoute(rd)
	if err != nil {
		return err
	}
	want["route.json"] = route
	if err := syncDir(sbDir, want); err != nil {
		return err
	}
	xr, err := emit.XrayRouting(rd)
	if err != nil {
		return err
	}
	return syncDir(filepath.Join(dist, "xray"), map[string][]byte{"routing.json": xr})
}

// syncDir makes dir contain exactly the given files (stale ones are removed).
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

// confData uses BASE_URL from the environment, else settings.base_url, so a
// local build and CI produce the same config.
func confData[T any](base, repo string, cats []Category, on map[string]T) emit.ConfData {
	if env := os.Getenv("BASE_URL"); env != "" {
		base = env
	}
	d := emit.ConfData{Repo: repo, BaseURL: strings.TrimRight(base, "/"), On: map[string]bool{}}
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
		if missing := missingEnv(s.RequiresEnv); missing != "" {
			out[i].status = "skipped"
			out[i].err = fmt.Errorf("%s not set", missing)
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

func missingEnv(vars []string) string {
	for _, v := range vars {
		if os.Getenv(v) == "" {
			return v
		}
	}
	return ""
}

func fetchOne(f *fetch.Fetcher, s Source) (parse.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	url := os.ExpandEnv(s.URL)
	body, err := f.Get(ctx, url, s.MaxBytes)
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

func printSummary(outs []outcome, cats []Category, stat func(string) (n, size, old int, oldExist bool, conflicts int)) {
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
	fmt.Fprintln(w, "LIST\tACTION\tRULES\tSIZE KB\tPREVIOUS\tDELTA\tIR-CONFLICTS\t")
	for _, c := range cats {
		n, size, old, oldExist, conf := stat(c.Name)
		if !c.Enabled {
			fmt.Fprintf(w, "%s\t%s\tdisabled\t\t\t\t\t\n", c.Name, c.Action)
			continue
		}
		prev, delta := "-", "-"
		if oldExist {
			prev, delta = fmt.Sprint(old), fmt.Sprintf("%+d", n-old)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%.1f\t%s\t%s\t%d\t\n", c.Name, c.Action, n, float64(size)/1024, prev, delta, conf)
	}
	w.Flush()
}
