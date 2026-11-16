package emit

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/aliraghebi/vpn-routing/internal/parse"
)

func TestGeoSiteDat(t *testing.T) {
	got := GeoSiteDat([]Tag{{Name: "ads", Domains: []parse.Domain{
		{Kind: parse.Suffix, Name: "a.io"}, {Kind: parse.Exact, Name: "b.io"}, {Kind: parse.Keyword, Name: "ad"},
	}}})
	want := []byte{
		0x0a, 0x1f, // GeoSiteList.entry, len 31
		0x0a, 0x03, 'A', 'D', 'S', // country_code
		0x12, 0x08, 0x08, 0x02, 0x12, 0x04, 'a', '.', 'i', 'o', // RootDomain a.io
		0x12, 0x08, 0x08, 0x03, 0x12, 0x04, 'b', '.', 'i', 'o', // Full b.io
		0x12, 0x04, 0x12, 0x02, 'a', 'd', // Plain (type omitted) ad
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  % x\nwant % x", got, want)
	}
}

func TestGeoIPDat(t *testing.T) {
	got := GeoIPDat([]Tag{{Name: "ir", CIDRs: []netip.Prefix{netip.MustParsePrefix("2.144.0.0/14"), netip.MustParsePrefix("::/0")}}})
	want := []byte{
		0x0a, 0x22, // GeoIPList.entry, len 34
		0x0a, 0x02, 'I', 'R',
		0x12, 0x08, 0x0a, 0x04, 2, 144, 0, 0, 0x10, 14, // v4, prefix 14
		0x12, 0x12, 0x0a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ::/0, prefix omitted
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got  % x\nwant % x", got, want)
	}
}

func TestSingBox(t *testing.T) {
	b, err := SingBoxDomains([]parse.Domain{{Kind: parse.Suffix, Name: "z.io"}, {Kind: parse.Exact, Name: "a.io"}, {Kind: parse.Keyword, Name: "ad"}})
	if err != nil {
		t.Fatal(err)
	}
	var rs struct {
		Version int `json:"version"`
		Rules   []map[string][]string
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	r := rs.Rules[0]
	if rs.Version != 2 || strings.Join(r["domain"], ",") != "a.io,z.io" || strings.Join(r["domain_suffix"], ",") != ".z.io" || strings.Join(r["domain_keyword"], ",") != "ad" {
		t.Fatalf("unexpected rule-set: %s", b)
	}
}

func TestRouteTemplates(t *testing.T) {
	d := RouteData{BaseURL: "https://x/release",
		Reject: []string{"geosite-ads", "geoip-malware"}, Proxy: []string{"geosite-sanctioned"}, Direct: []string{"geosite-ir", "geoip-ir"},
		All:        []string{"geosite-ads", "geoip-malware", "geosite-sanctioned", "geosite-ir", "geoip-ir"},
		RejectSite: []string{"ads"}, RejectIP: []string{"malware"}, ProxySite: []string{"sanctioned"}}
	for name, fn := range map[string]func(RouteData) ([]byte, error){"sing-box": SingBoxRoute, "xray": XrayRouting} {
		b, err := fn(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(b), "ads") || !strings.Contains(string(b), "sanctioned") {
			t.Fatalf("%s: missing tags:\n%s", name, b)
		}
	}
	d.Proxy, d.ProxySite, d.RejectIP = nil, nil, nil // optional sections must still render valid JSON
	for _, fn := range []func(RouteData) ([]byte, error){SingBoxRoute, XrayRouting} {
		if _, err := fn(d); err != nil {
			t.Fatal(err)
		}
	}
}
