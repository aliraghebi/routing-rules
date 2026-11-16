package emit

import "encoding/json"

// karingRule is one group in Karing's "diversion rules custom" export format
// (field order matches what Karing writes).
type karingRule struct {
	Outbound string   `json:"outbound"`
	Name     string   `json:"name"`
	Switch   bool     `json:"switch"`
	Or       bool     `json:"or"`
	RuleSet  []string `json:"rule_set"`
}

// Karing renders custom diversion rules that reference our sing-box .srs
// rule-sets on the given mirror. Block comes first, then Direct; anything
// unmatched follows Karing's own default (the selected proxy).
func Karing(base string, reject, direct []string) ([]byte, error) {
	urls := func(tags []string) []string {
		out := make([]string, 0, len(tags))
		for _, t := range tags {
			out = append(out, base+"/"+t+".srs")
		}
		return out
	}
	doc := struct {
		Rules []karingRule `json:"rules"`
	}{[]karingRule{
		{Outbound: "block", Name: "🚫 Block", Switch: true, Or: true, RuleSet: urls(reject)},
		{Outbound: "direct", Name: "✅ Direct", Switch: true, Or: true, RuleSet: urls(direct)},
	}}
	b, err := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n'), err
}
