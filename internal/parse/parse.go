// Package parse turns upstream list formats into normalized domains and CIDRs.
package parse

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Kind is the Shadowrocket match type of a domain rule.
type Kind uint8

const (
	Suffix  Kind = iota // DOMAIN-SUFFIX
	Exact               // DOMAIN
	Keyword             // DOMAIN-KEYWORD
)

// Domain is a single domain rule.
type Domain struct {
	Kind Kind
	Name string
}

// Result holds everything a parser extracted from one source.
type Result struct {
	Domains []Domain
	CIDRs   []netip.Prefix
}

func (r *Result) Append(o Result) {
	r.Domains = append(r.Domains, o.Domains...)
	r.CIDRs = append(r.CIDRs, o.CIDRs...)
}

// Options tune a parser for one source.
type Options struct {
	// Match is the kind used for plain domains (hosts/domains formats).
	Match Kind
	// Filter keeps only JSON objects whose key equals the value (e.g. service=CLOUDFRONT).
	Filter map[string]string
	// Country is the ISO code for country databases (dbip-csv).
	Country string
	// Include resolves v2fly "include:" targets.
	Include func(name string) ([]byte, error)
}

// Func parses one source body.
type Func func(data []byte, opt Options) (Result, error)

// Formats maps the sources.yaml format name to its parser.
var Formats = map[string]Func{
	"hosts":    Hosts,
	"domains":  Domains,
	"abp":      ABP,
	"v2fly":    V2Fly,
	"cidr":     CIDRText,
	"json":     JSON,
	"dbip-csv": DBIP,
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// NormalizeDomain lowercases, punycodes and validates a hostname.
// It rejects IP literals, single-label names and invalid labels.
func NormalizeDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return "", false
	}
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	s = strings.ToLower(s)
	if !ascii {
		var err error
		if s, err = idnaProfile.ToASCII(s); err != nil {
			return "", false
		}
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" { // numeric TLD = IP-ish garbage
		return "", false
	}
	if s == "localhost.localdomain" {
		return "", false
	}
	return s, true
}

// lines yields trimmed lines with "#" and "!" comments removed.
func lines(data []byte, fn func(string)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '!' {
			continue
		}
		fn(l)
	}
}

func (r *Result) addDomain(k Kind, raw string) {
	if strings.HasPrefix(raw, "*.") {
		raw, k = raw[2:], Suffix
	} else if strings.HasPrefix(raw, ".") {
		raw, k = raw[1:], Suffix
	}
	if d, ok := NormalizeDomain(raw); ok {
		r.Domains = append(r.Domains, Domain{k, d})
	}
}

// Hosts parses "0.0.0.0 a.com b.com" style files.
func Hosts(data []byte, opt Options) (Result, error) {
	var r Result
	lines(data, func(l string) {
		f := strings.Fields(l)
		if len(f) < 2 {
			return
		}
		if _, err := netip.ParseAddr(f[0]); err != nil {
			return
		}
		for _, h := range f[1:] {
			r.addDomain(opt.Match, h)
		}
	})
	return r, nil
}

// Domains parses one domain per line (first field only).
func Domains(data []byte, opt Options) (Result, error) {
	var r Result
	lines(data, func(l string) {
		r.addDomain(opt.Match, strings.Fields(l)[0])
	})
	return r, nil
}

// ABP extracts network-level "||domain^" rules only. Exceptions, cosmetic,
// regex, wildcard and modifier-scoped rules are skipped because they cannot be
// expressed as plain domain rules without changing their meaning.
func ABP(data []byte, opt Options) (Result, error) {
	var r Result
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(l, "||") {
			continue
		}
		body, mods, _ := strings.Cut(l[2:], "$")
		if mods != "" && !safeModifiers(mods) {
			continue
		}
		host, ok := strings.CutSuffix(body, "^")
		if !ok || strings.ContainsAny(host, "*/|^:") {
			continue
		}
		r.addDomain(Suffix, host)
	}
	return r, nil
}

func safeModifiers(m string) bool {
	for _, x := range strings.Split(m, ",") {
		switch x {
		case "important", "all", "document", "doc":
		default:
			return false
		}
	}
	return true
}

// V2Fly parses v2fly/domain-list-community data files, following include:
// recursively. "include:x @a @-b" keeps only entries with attr a and without b.
// regexp: entries are skipped (Shadowrocket rule-sets have no safe equivalent).
func V2Fly(data []byte, opt Options) (Result, error) {
	return v2fly(data, opt, map[string]bool{}, 0)
}

type v2entry struct {
	d     Domain
	attrs []string
}

func v2fly(data []byte, opt Options, seen map[string]bool, depth int) (Result, error) {
	es, err := v2flyEntries(data, opt, seen, depth)
	var r Result
	for _, e := range es {
		r.Domains = append(r.Domains, e.d)
	}
	return r, err
}

func v2flyEntries(data []byte, opt Options, seen map[string]bool, depth int) ([]v2entry, error) {
	if depth > 16 {
		return nil, fmt.Errorf("v2fly: include depth exceeded")
	}
	var out []v2entry
	var firstErr error
	lines(data, func(l string) {
		f := strings.Fields(l)
		val := f[0]
		var attrs []string
		for _, t := range f[1:] {
			if strings.HasPrefix(t, "@") {
				attrs = append(attrs, t[1:])
			} // "&affiliation" tokens are ignored
		}
		typ, v, ok := strings.Cut(val, ":")
		if !ok {
			typ, v = "domain", val
		}
		switch typ {
		case "include":
			if opt.Include == nil {
				return
			}
			if seen[v] { // include cycle
				return
			}
			body, err := opt.Include(v)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("v2fly include %s: %w", v, err)
				}
				return
			}
			seen[v] = true
			sub, err := v2flyEntries(body, opt, seen, depth+1)
			delete(seen, v)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for _, e := range sub {
				if attrMatch(e.attrs, attrs) {
					out = append(out, e)
				}
			}
		case "domain", "full", "keyword":
			k := map[string]Kind{"domain": Suffix, "full": Exact, "keyword": Keyword}[typ]
			if k == Keyword {
				v = strings.ToLower(v)
				if v != "" && !strings.ContainsAny(v, " \t") {
					out = append(out, v2entry{Domain{Keyword, v}, attrs})
				}
				return
			}
			if d, ok := NormalizeDomain(v); ok {
				out = append(out, v2entry{Domain{k, d}, attrs})
			}
		}
	})
	return out, firstErr
}

func attrMatch(have, want []string) bool {
	for _, w := range want {
		neg := strings.HasPrefix(w, "-") || strings.HasPrefix(w, "!")
		name := strings.TrimLeft(w, "-!")
		has := false
		for _, h := range have {
			if h == name {
				has = true
				break
			}
		}
		if has == neg {
			return false
		}
	}
	return true
}

// CIDRText parses one CIDR, address, or "a-b" range per line (first field).
func CIDRText(data []byte, _ Options) (Result, error) {
	var r Result
	lines(data, func(l string) {
		f := strings.FieldsFunc(l, func(c rune) bool { return c == ' ' || c == '\t' || c == ',' || c == ';' })
		if len(f) > 0 {
			r.CIDRs = append(r.CIDRs, ParsePrefixish(f[0])...)
		}
	})
	return r, nil
}

// ParsePrefixish accepts "a/len", a bare address, or "a-b".
func ParsePrefixish(s string) []netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return []netip.Prefix{p.Masked()}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
		b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
		if err1 == nil && err2 == nil {
			return RangeToPrefixes(a, b)
		}
	}
	return nil
}
