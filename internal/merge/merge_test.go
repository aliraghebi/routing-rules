package merge

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/aliraghebi/routing-rules/internal/parse"
)

func D(k parse.Kind, n string) parse.Domain { return parse.Domain{Kind: k, Name: n} }

const (
	S = parse.Suffix
	E = parse.Exact
	K = parse.Keyword
)

func TestDomains(t *testing.T) {
	in := []parse.Domain{D(E, "a.example.com"), D(S, "example.com"), D(S, "x.example.com"), D(E, "example.com"),
		D(E, "other.org"), D(E, "other.org"), D(S, "sub.other.org"), D(K, "ads"), D(K, "ads")}
	want := []parse.Domain{D(S, "example.com"), D(S, "sub.other.org"), D(E, "other.org"), D(K, "ads")}
	if got := Domains(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDomainsTLD(t *testing.T) {
	// A single-label suffix must survive and still cover everything under it.
	in := []parse.Domain{D(S, "ir"), D(S, "digikala.ir"), D(E, "a.example.ir"), D(S, "example.com")}
	want := []parse.Domain{D(S, "example.com"), D(S, "ir")}
	if got := Domains(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRemoveAllowed(t *testing.T) {
	in := []parse.Domain{D(S, "google.com"), D(E, "mail.google.com"), D(S, "x.mail.google.com"), D(E, "ads.com"), D(K, "mail")}
	kept, removed := RemoveAllowed(in, []string{"mail.google.com"})
	if !reflect.DeepEqual(kept, []parse.Domain{D(E, "ads.com")}) || len(removed) != 4 {
		t.Fatalf("kept %v removed %v", kept, removed)
	}
}

func TestRemoveConflicts(t *testing.T) {
	prot := []parse.Domain{D(S, "digikala.com"), D(E, "shop.example.ir")}
	in := []parse.Domain{D(S, "digikala.com"), D(S, "ads.digikala.com"), D(S, "example.ir"), D(E, "shop.example.ir"), D(E, "x.shop.example.ir"), D(K, "kala"), D(E, "evil.com")}
	kept, _ := RemoveConflicts(in, prot)
	want := []parse.Domain{D(S, "ads.digikala.com"), D(E, "x.shop.example.ir"), D(E, "evil.com")}
	if !reflect.DeepEqual(kept, want) {
		t.Fatalf("got %v want %v", kept, want)
	}
}

func P(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestCIDRs(t *testing.T) {
	in := P("10.0.1.0/24", "2001:db8::/33", "10.0.0.0/24", "10.0.0.5/32", "2001:db8:8000::/33", "192.168.0.0/16", "::ffff:1.2.3.0/120", "255.255.255.255/32")
	want := P("1.2.3.0/24", "10.0.0.0/23", "192.168.0.0/16", "255.255.255.255/32", "2001:db8::/32")
	if got := CIDRs(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRemoveCIDRConflicts(t *testing.T) {
	prot := CIDRs(P("2.144.0.0/14", "5.22.0.0/24"))
	kept, removed := RemoveCIDRConflicts(P("2.144.1.1/32", "2.0.0.0/8", "5.22.0.0/24", "8.8.8.8/32"), prot)
	if !reflect.DeepEqual(kept, P("2.144.1.1/32", "8.8.8.8/32")) || len(removed) != 2 {
		t.Fatalf("kept %v removed %v", kept, removed)
	}
}

func TestRemoveMatched(t *testing.T) {
	in := []parse.Domain{D(S, "yektanet.com"), D(E, "cdn.yektanet.com"), D(S, "digikala.com"), D(E, "tapsell.ir"), D(S, "sabaidea.cloud"), D(K, "yektanet")}
	kept, _ := RemoveMatched(in, []parse.Domain{D(S, "yektanet.com"), D(E, "tapsell.ir"), D(E, "sabaidea.cloud"), D(K, "digi")})
	if want := []parse.Domain{D(S, "digikala.com"), D(S, "sabaidea.cloud"), D(K, "yektanet")}; !reflect.DeepEqual(kept, want) {
		t.Fatalf("got %v want %v", kept, want)
	}
}

func TestComplement(t *testing.T) {
	got := Complement(P("0.0.0.0/1", "192.168.0.0/16", "::/1"))
	want := P("128.0.0.0/2", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15",
		"192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5",
		"208.0.0.0/4", "224.0.0.0/3", "8000::/1")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if all := Complement(nil); !reflect.DeepEqual(all, P("0.0.0.0/0", "::/0")) {
		t.Fatalf("complement of nothing: %v", all)
	}
	if none := Complement(P("0.0.0.0/0", "::/0")); len(none) != 0 {
		t.Fatalf("complement of everything: %v", none)
	}
}
