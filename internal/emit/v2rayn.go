package emit

import "encoding/json"

// v2raynRule is one entry in v2rayN / v2rayNG custom routing rules (the JSON
// array those apps import; same fields Chocolate4U's v2rayN templates use).
type v2raynRule struct {
	Remarks     string   `json:"remarks"`
	OutboundTag string   `json:"outboundTag"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// V2rayNRouting renders routing rules that use this project's geosite.dat /
// geoip.dat tags, in the same order as the other configs.
func V2rayNRouting(d RouteData) ([]byte, error) {
	tags := func(prefix string, names []string) []string {
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, prefix+n)
		}
		return out
	}
	var rules []v2raynRule
	if len(d.EarlyIP) > 0 {
		rules = append(rules, v2raynRule{Remarks: "DNS block-page IPs - block", OutboundTag: "block", IP: tags("geoip:", d.EarlyIP), Enabled: true})
	}
	if len(d.PrivateSite) > 0 {
		rules = append(rules, v2raynRule{Remarks: "Local names (lan, local, localhost, routers) - direct", OutboundTag: "direct", Domain: tags("geosite:", d.PrivateSite), Enabled: true})
	}
	rules = append(rules, v2raynRule{Remarks: "Private IPs - direct", OutboundTag: "direct", IP: []string{"geoip:private"}, Enabled: true})
	rules = append(rules, v2raynRule{Remarks: "Ads, malware, phishing, cryptominers - block", OutboundTag: "block", Domain: tags("geosite:", d.RejectSite), Enabled: true})
	if len(d.RejectIP) > 0 {
		rules = append(rules, v2raynRule{Remarks: "Malicious IPs - block", OutboundTag: "block", IP: tags("geoip:", d.RejectIP), Enabled: true})
	}
	if len(d.ProxySite) > 0 {
		rules = append(rules, v2raynRule{Remarks: "Sites that block Iranian IPs - proxy", OutboundTag: "proxy", Domain: tags("geosite:", d.ProxySite), Enabled: true})
	}
	rules = append(rules,
		v2raynRule{Remarks: "Iranian domains - direct", OutboundTag: "direct", Domain: []string{"geosite:ir"}, Enabled: true},
		v2raynRule{Remarks: "Iranian IPs - direct", OutboundTag: "direct", IP: []string{"geoip:ir"}, Enabled: true},
		v2raynRule{Remarks: "Everything else - proxy", OutboundTag: "proxy", Port: "0-65535", Enabled: true},
	)
	b, err := json.MarshalIndent(rules, "", "  ")
	return append(b, '\n'), err
}
