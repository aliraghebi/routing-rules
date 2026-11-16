package emit

import (
	"encoding/json"
	"net/netip"
	"slices"

	"github.com/aliraghebi/vpn-routing/internal/parse"
)

// SingBoxVersion is the source rule-set format version, which also sets the
// compiled .srs version. Version 1 covers every rule type used here and is
// read by all sing-box releases since 1.8; version 2 (sing-box 1.10+) only
// stores domain_suffix more compactly, and Karing's bundled core rejects it.
const SingBoxVersion = 1

type sbRule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
}

type sbRuleSet struct {
	Version int      `json:"version"`
	Rules   []sbRule `json:"rules"`
}

// SingBoxDomains renders a geosite-style source rule-set. A suffix rule is
// written as domain "x" plus domain_suffix ".x" (the same expansion sing-box's
// own geosite converter uses), so matching does not depend on how a given
// sing-box version treats a domain_suffix without a leading dot.
func SingBoxDomains(domains []parse.Domain) ([]byte, error) {
	var r sbRule
	for _, d := range domains {
		switch d.Kind {
		case parse.Exact:
			r.Domain = append(r.Domain, d.Name)
		case parse.Suffix:
			r.Domain = append(r.Domain, d.Name)
			r.DomainSuffix = append(r.DomainSuffix, "."+d.Name)
		case parse.Keyword:
			r.DomainKeyword = append(r.DomainKeyword, d.Name)
		}
	}
	slices.Sort(r.Domain) // suffix apexes and exact names interleave
	return render(r)
}

// SingBoxCIDRs renders a geoip-style source rule-set.
func SingBoxCIDRs(cidrs []netip.Prefix) ([]byte, error) {
	var r sbRule
	for _, p := range cidrs {
		r.IPCIDR = append(r.IPCIDR, p.String())
	}
	return render(r)
}

func render(r sbRule) ([]byte, error) {
	// One entry per line keeps git diffs readable.
	b, err := json.MarshalIndent(sbRuleSet{SingBoxVersion, []sbRule{r}}, "", "  ")
	return append(b, '\n'), err
}
