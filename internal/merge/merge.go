// Package merge dedupes, aggregates and filters normalized rules.
package merge

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/OWNER/shadowrocket-config/internal/parse"
)

// parents calls fn for name and each parent suffix ("a.b.c" -> "a.b.c", "b.c", "c").
func parents(name string, fn func(string) bool) {
	for {
		if fn(name) {
			return
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return
		}
		name = name[i+1:]
	}
}

// Domains dedupes rules, drops entries covered by a DOMAIN-SUFFIX parent and
// returns them sorted by kind then name.
func Domains(in []parse.Domain) []parse.Domain {
	suffix := map[string]bool{}
	for _, d := range in {
		if d.Kind == parse.Suffix {
			suffix[d.Name] = true
		}
	}
	seen := map[parse.Domain]bool{}
	var out []parse.Domain
	for _, d := range in {
		if seen[d] {
			continue
		}
		seen[d] = true
		if d.Kind != parse.Keyword {
			covered := false
			name := d.Name
			if d.Kind == parse.Suffix { // a suffix is only covered by a strict parent
				i := strings.IndexByte(name, '.')
				name = name[i+1:]
			}
			parents(name, func(p string) bool { covered = suffix[p]; return covered })
			if covered {
				continue
			}
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b parse.Domain) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// Matches reports whether rule d would match hostname name.
func Matches(d parse.Domain, name string) bool {
	switch d.Kind {
	case parse.Exact:
		return name == d.Name
	case parse.Suffix:
		return name == d.Name || strings.HasSuffix(name, "."+d.Name)
	default:
		return strings.Contains(name, d.Name)
	}
}

// RemoveAllowed drops rules that would match an allowlisted domain, plus
// rules for the allowlisted domain's subdomains.
func RemoveAllowed(in []parse.Domain, allow []string) (kept, removed []parse.Domain) {
	if len(allow) == 0 {
		return in, nil
	}
	allowSet := map[string]bool{}
	for _, a := range allow {
		allowSet[a] = true
	}
	for _, d := range in {
		drop := false
		if d.Kind == parse.Keyword {
			for _, a := range allow {
				if Matches(d, a) {
					drop = true
					break
				}
			}
		} else {
			// d is the allowlisted name, one of its subdomains, or (suffix) a parent of it.
			parents(d.Name, func(p string) bool { drop = allowSet[p]; return drop })
			if !drop && d.Kind == parse.Suffix {
				for _, a := range allow {
					if Matches(d, a) {
						drop = true
						break
					}
				}
			}
		}
		if drop {
			removed = append(removed, d)
		} else {
			kept = append(kept, d)
		}
	}
	return kept, removed
}

// RemoveConflicts drops rules that would match any protected domain rule's
// own name (e.g. a REJECT entry that would block a whole ir-domains site).
// More specific rules (a REJECT for ads.site.ir under DIRECT site.ir) are kept.
func RemoveConflicts(in, protected []parse.Domain) (kept, removed []parse.Domain) {
	exact := map[string]bool{}
	anc := map[string]bool{} // every protected name and all its parents
	for _, p := range protected {
		if p.Kind == parse.Keyword {
			continue
		}
		exact[p.Name] = true
		parents(p.Name, func(s string) bool { anc[s] = true; return false })
	}
	for _, d := range in {
		var bad bool
		switch d.Kind {
		case parse.Exact:
			bad = exact[d.Name]
		case parse.Suffix:
			bad = anc[d.Name]
		case parse.Keyword:
			for n := range exact {
				if strings.Contains(n, d.Name) {
					bad = true
					break
				}
			}
		}
		if bad {
			removed = append(removed, d)
		} else {
			kept = append(kept, d)
		}
	}
	return kept, removed
}

type span struct {
	lo, hi parse.U128
	v4     bool
}

// CIDRs merges overlapping and adjacent prefixes into the minimal sorted set
// (IPv4 first, then IPv6).
func CIDRs(in []netip.Prefix) []netip.Prefix {
	spans := make([]span, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		lo := parse.AddrToU128(p.Addr())
		hi := lastOf(lo, p.Addr().BitLen()-p.Bits())
		spans = append(spans, span{lo, hi, p.Addr().Is4()})
	}
	slices.SortFunc(spans, func(a, b span) int {
		if a.v4 != b.v4 {
			if a.v4 {
				return -1
			}
			return 1
		}
		return a.lo.Cmp(b.lo)
	})
	var out []netip.Prefix
	for i := 0; i < len(spans); {
		cur := spans[i]
		j := i + 1
		for ; j < len(spans) && spans[j].v4 == cur.v4; j++ {
			// merge if overlapping or adjacent (cur.hi+1 >= next.lo, guarding overflow)
			n := spans[j]
			if n.lo.Cmp(cur.hi) > 0 && n.lo != cur.hi.Add1() {
				break
			}
			if n.hi.Cmp(cur.hi) > 0 {
				cur.hi = n.hi
			}
		}
		out = append(out, parse.RangeToPrefixes(parse.U128ToAddr(cur.lo, cur.v4), parse.U128ToAddr(cur.hi, cur.v4))...)
		i = j
	}
	return out
}

// lastOf returns lo with the low n bits set.
func lastOf(lo parse.U128, n int) parse.U128 {
	switch {
	case n >= 128:
		return parse.U128{Hi: ^uint64(0), Lo: ^uint64(0)}
	case n >= 64:
		return parse.U128{Hi: lo.Hi | (1<<(n-64) - 1), Lo: ^uint64(0)}
	default:
		return parse.U128{Hi: lo.Hi, Lo: lo.Lo | (1<<n - 1)}
	}
}

// RemoveCIDRConflicts drops prefixes that equal or contain any protected
// prefix. protected must be the output of CIDRs (sorted, non-overlapping).
func RemoveCIDRConflicts(in, protected []netip.Prefix) (kept, removed []netip.Prefix) {
	for _, r := range in {
		i, _ := slices.BinarySearchFunc(protected, r.Addr(), func(p netip.Prefix, a netip.Addr) int {
			return p.Addr().Compare(a)
		})
		if i < len(protected) && r.Bits() <= protected[i].Bits() && r.Contains(protected[i].Addr()) {
			removed = append(removed, r)
		} else {
			kept = append(kept, r)
		}
	}
	return kept, removed
}
