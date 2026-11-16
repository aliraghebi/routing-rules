package emit

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"github.com/aliraghebi/routing-rules/internal/parse"
)

// Tag is one geosite/geoip entry (v2ray) or one rule-set (sing-box).
type Tag struct {
	Name    string
	Domains []parse.Domain
	CIDRs   []netip.Prefix
}

// v2ray routercommon.Domain.Type
const (
	v2Plain      = 0 // substring (keyword)
	v2RootDomain = 2 // domain and all subdomains
	v2Full       = 3 // exact domain
)

// Protobuf wire helpers (wire type 0 = varint, 2 = length-delimited).
func pbVarint(b []byte, field int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3)
	return binary.AppendUvarint(b, v)
}

func pbBytes(b []byte, field int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

// GeoSiteDat encodes a v2ray/xray GeoSiteList:
// GeoSiteList{1: repeated GeoSite{1: country_code, 2: repeated Domain{1: type, 2: value}}}.
// Tags are written in the given order; callers pass them sorted for stable output.
func GeoSiteDat(tags []Tag) []byte {
	var out, site, dom []byte
	for _, t := range tags {
		site = pbBytes(site[:0], 1, []byte(strings.ToUpper(t.Name)))
		for _, d := range t.Domains {
			typ := map[parse.Kind]uint64{parse.Suffix: v2RootDomain, parse.Exact: v2Full, parse.Keyword: v2Plain}[d.Kind]
			dom = dom[:0]
			if typ != 0 { // proto3 omits default values
				dom = pbVarint(dom, 1, typ)
			}
			dom = pbBytes(dom, 2, []byte(d.Name))
			site = pbBytes(site, 2, dom)
		}
		out = pbBytes(out, 1, site)
	}
	return out
}

// GeoIPDat encodes a v2ray/xray GeoIPList:
// GeoIPList{1: repeated GeoIP{1: country_code, 2: repeated CIDR{1: ip bytes, 2: prefix}}}.
func GeoIPDat(tags []Tag) []byte {
	var out, geo, cidr []byte
	for _, t := range tags {
		geo = pbBytes(geo[:0], 1, []byte(strings.ToUpper(t.Name)))
		for _, p := range t.CIDRs {
			cidr = pbBytes(cidr[:0], 1, p.Addr().AsSlice())
			if p.Bits() != 0 {
				cidr = pbVarint(cidr, 2, uint64(p.Bits()))
			}
			geo = pbBytes(geo, 2, cidr)
		}
		out = pbBytes(out, 1, geo)
	}
	return out
}

// Private is the address space v2ray's geoip:private covers. Replacing
// geoip.dat would otherwise drop this commonly used tag.
var Private = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()
