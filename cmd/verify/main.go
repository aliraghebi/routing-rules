// Command verify tests the compiled rule-sets and the PAC file against the
// known answers in data/canaries.txt, using the clients' own tools: sing-box
// for .srs, mihomo for .mrs and Node.js for the PAC file. cmd/build writes
// the checks to out/checks.json; CI runs this after compiling.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type check struct {
	File  string `json:"file"`
	Q     string `json:"q"`
	Match bool   `json:"match"`
}

func main() {
	checksPath := flag.String("checks", "out/checks.json", "checks written by cmd/build")
	srsDir := flag.String("srs", "out/srs", "compiled sing-box rule-sets")
	mrsDir := flag.String("mrs", "out/mrs", "compiled mihomo rule-sets")
	pac := flag.String("pac", "dist/proxy.pac", "PAC file")
	flag.Parse()
	log.SetFlags(0)

	b, err := os.ReadFile(*checksPath)
	if err != nil {
		log.Fatalf("::error::%v", err)
	}
	var checks []check
	if err := json.Unmarshal(b, &checks); err != nil {
		log.Fatalf("::error::%s: %v", *checksPath, err)
	}
	if len(checks) == 0 {
		log.Fatalf("::error::%s has no checks", *checksPath)
	}
	var sets, pacChecks []check
	for _, c := range checks {
		if c.File == "proxy.pac" {
			pacChecks = append(pacChecks, c)
		} else {
			sets = append(sets, c)
		}
	}

	var bad []string
	bad = append(bad, checkSRS(*srsDir, sets)...)
	bad = append(bad, checkMRS(*mrsDir, sets)...)
	bad = append(bad, checkPAC(*pac, pacChecks)...)
	log.Printf("verify: %d rule-set checks × 2 tools, %d PAC checks, %d failed", len(sets), len(pacChecks), len(bad))
	for _, m := range bad {
		log.Printf("::error::%s", m)
	}
	if len(bad) > 0 {
		os.Exit(1)
	}
}

func want(match bool) string {
	if match {
		return "should match"
	}
	return "should not match"
}

// checkSRS asks sing-box whether each .srs file matches its query.
func checkSRS(dir string, checks []check) []string {
	var mu sync.Mutex
	var bad []string
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	for _, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, _ := exec.Command("sing-box", "rule-set", "match", "-f", "binary", filepath.Join(dir, c.File+".srs"), c.Q).CombinedOutput()
			if strings.Contains(string(out), "match rules") != c.Match {
				mu.Lock()
				bad = append(bad, fmt.Sprintf("sing-box: %s.srs %s %s", c.File, want(c.Match), c.Q))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return bad
}

// checkMRS decodes each .mrs file once with mihomo and matches the queries
// against its rules.
func checkMRS(dir string, checks []check) []string {
	tmp, err := os.MkdirTemp("", "verify-mrs")
	if err != nil {
		return []string{err.Error()}
	}
	defer os.RemoveAll(tmp)
	sets := map[string]*ruleSet{}
	var bad []string
	for _, c := range checks {
		rs, ok := sets[c.File]
		if !ok {
			if rs, err = dumpMRS(dir, tmp, c.File); err != nil {
				bad = append(bad, err.Error())
			}
			sets[c.File] = rs
		}
		if rs != nil && rs.match(c.Q) != c.Match {
			bad = append(bad, fmt.Sprintf("mihomo: %s.mrs %s %s", c.File, want(c.Match), c.Q))
		}
	}
	return bad
}

type ruleSet struct {
	suffix, exact map[string]bool
	cidrs         []netip.Prefix
}

func dumpMRS(dir, tmp, name string) (*ruleSet, error) {
	behavior := "domain"
	if strings.HasPrefix(name, "geoip-") {
		behavior = "ipcidr"
	}
	dump := filepath.Join(tmp, name+".txt")
	if out, err := exec.Command("mihomo", "convert-ruleset", behavior, "mrs", filepath.Join(dir, name+".mrs"), dump).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mihomo: decoding %s.mrs: %v: %s", name, err, bytes.TrimSpace(out))
	}
	b, err := os.ReadFile(dump)
	if err != nil {
		return nil, err
	}
	rs := &ruleSet{suffix: map[string]bool{}, exact: map[string]bool{}}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case behavior == "ipcidr":
			p, err := netip.ParsePrefix(l)
			if err != nil {
				return nil, fmt.Errorf("mihomo: %s.mrs: unexpected line %q", name, l)
			}
			rs.cidrs = append(rs.cidrs, p)
		case strings.HasPrefix(l, "+."):
			rs.suffix[l[2:]] = true
		case strings.ContainsAny(l, "*+"): // cmd/build only writes "+." and exact rules
			return nil, fmt.Errorf("mihomo: %s.mrs: unexpected rule %q", name, l)
		default:
			rs.exact[l] = true
		}
	}
	return rs, nil
}

func (rs *ruleSet) match(q string) bool {
	if ip, err := netip.ParseAddr(q); err == nil {
		for _, p := range rs.cidrs {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	if rs.exact[q] {
		return true
	}
	for h := q; ; {
		if rs.suffix[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// pacScript evaluates the PAC file in Node.js and prints one line per failed
// check. PAC helpers the file uses are stubbed.
const pacScript = `
const fs = require("fs");
global.isPlainHostName = h => !h.includes(".");
eval(fs.readFileSync(process.argv[1], "utf8"));
for (const c of JSON.parse(process.argv[2])) {
  const direct = FindProxyForURL("https://" + c.q + "/", c.q) === "DIRECT";
  if (direct !== c.match) console.log("PAC: " + c.q + (c.match ? " should go DIRECT" : " should not go DIRECT"));
}
`

func checkPAC(path string, checks []check) []string {
	if len(checks) == 0 {
		return nil
	}
	js, _ := json.Marshal(checks)
	out, err := exec.Command("node", "-e", pacScript, path, string(js)).CombinedOutput()
	if err != nil {
		return []string{fmt.Sprintf("PAC: %v: %s", err, bytes.TrimSpace(out))}
	}
	var bad []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			bad = append(bad, l)
		}
	}
	return bad
}
