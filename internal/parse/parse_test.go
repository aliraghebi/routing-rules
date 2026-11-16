package parse

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rules(r Result) []string {
	var out []string
	for _, d := range r.Domains {
		out = append(out, [...]string{"S:", "E:", "K:"}[d.Kind]+d.Name)
	}
	for _, p := range r.CIDRs {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestParsers(t *testing.T) {
	v2include := func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join("..", "..", "testdata", "v2fly", name))
	}
	tests := []struct {
		name, format, file string
		opt                Options
		want               []string
	}{
		{"hosts", "hosts", "hosts.txt", Options{Match: Exact},
			[]string{"E:ads.example.com", "E:tracker.example.net", "E:xn--bcher-kva.de"}},
		{"domains", "domains", "domains.txt", Options{Match: Suffix},
			[]string{"S:example.com", "S:sub.example.com", "S:wild.example.org"}},
		{"abp", "abp", "abp.txt", Options{},
			[]string{"S:ads.example.com", "S:tracker.example.net"}},
		{"v2fly", "v2fly", "v2fly/root", Options{Include: v2include},
			[]string{"E:exact.example.com", "K:tracker", "S:ads.example", "S:child.example", "S:cnads.example", "S:neutral.example", "S:plain.example", "S:suffix.example"}},
		{"cidr", "cidr", "cidr.txt", Options{},
			[]string{"1.2.3.0/24", "10.0.0.1/32", "10.0.1.0/24", "2001:db8::/32"}},
		{"html", "html-cidr", "page.html", Options{},
			[]string{"185.143.232.0/22", "2a0b:4d07::/32", "94.101.182.0/27"}},
		{"aws", "json", "aws.json", Options{Filter: map[string]string{"service": "CLOUDFRONT"}},
			[]string{"13.32.0.0/15", "2600:9000::/28"}},
		{"fastly", "json", "fastly.json", Options{},
			[]string{"151.101.0.0/16", "23.235.32.0/20", "2a04:4e40::/32"}},
		{"ripe", "json", "ripe.json", Options{},
			[]string{"2.144.0.0/14", "2a01:5ec0::/32", "5.22.0.0/23"}},
		{"maxmind", "maxmind-csv", "maxmind.zip", Options{Country: "IR"},
			[]string{"2.144.0.0/14", "2a01:5ec0::/32", "5.160.0.0/16"}},
		{"ip2location-v4", "ip2location", "ip2location.csv", Options{Country: "IR"},
			[]string{"2.148.0.0/14"}},
		{"ip2location-v6", "ip2location", "ip2location6.csv", Options{Country: "ir"},
			[]string{"2.148.0.0/14", "2a01:5ec0::/32"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Formats[tc.format](fixture(t, tc.file), tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			if got := rules(r); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := map[string]string{
		"Example.COM.":  "example.com",
		"bücher.de":     "xn--bcher-kva.de",
		"_dmarc.ex.com": "_dmarc.ex.com",
		"1.2.3.4":       "",
		"[::1]":         "",
		"localhost":     "",
		"a..b":          "",
		"-a.com":        "",
		"a.123":         "",
		strings.Repeat("a", 64) + ".com": "",
	}
	for in, want := range tests {
		got, ok := NormalizeDomain(in)
		if got != want || ok != (want != "") {
			t.Errorf("NormalizeDomain(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func TestRangeToPrefixes(t *testing.T) {
	tests := []struct {
		a, b string
		want []string
	}{
		{"10.0.0.0", "10.0.0.255", []string{"10.0.0.0/24"}},
		{"10.0.0.1", "10.0.0.6", []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"::/0"}},
		{"2001:db8::", "2001:db8:0:1:ffff:ffff:ffff:ffff", []string{"2001:db8::/63"}},
		{"10.0.0.5", "10.0.0.5", []string{"10.0.0.5/32"}},
		{"10.0.0.5", "10.0.0.4", nil},
	}
	for _, tc := range tests {
		var got []string
		for _, p := range RangeToPrefixes(netip.MustParseAddr(tc.a), netip.MustParseAddr(tc.b)) {
			got = append(got, p.String())
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s-%s: got %v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
