// Package emit renders Shadowrocket rule lists and the config file.
package emit

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/aliraghebi/shadowrocket-config/internal/parse"
)

var kindPrefix = [...]string{parse.Suffix: "DOMAIN-SUFFIX", parse.Exact: "DOMAIN", parse.Keyword: "DOMAIN-KEYWORD"}

// List renders a RULE-SET file. Inputs must already be sorted (merge output),
// so identical inputs give byte-identical output.
func List(name string, domains []parse.Domain, cidrs []netip.Prefix) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# NAME: %s\n# TOTAL: %d\n", name, len(domains)+len(cidrs))
	for _, d := range domains {
		fmt.Fprintf(&b, "%s,%s\n", kindPrefix[d.Kind], d.Name)
	}
	for _, p := range cidrs {
		if p.Addr().Is4() {
			fmt.Fprintf(&b, "IP-CIDR,%s,no-resolve\n", p)
		} else {
			fmt.Fprintf(&b, "IP-CIDR6,%s,no-resolve\n", p)
		}
	}
	return b.Bytes()
}

// CountRules counts non-comment, non-empty lines of a rendered list.
func CountRules(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && l[0] != '#' {
			n++
		}
	}
	return n
}

//go:embed shadowrocket.conf.tmpl
var confTmpl string

var tmpl = template.Must(template.New("conf").Parse(confTmpl))

// ConfData feeds the config template.
type ConfData struct {
	Repo    string
	BaseURL string
	Reject  []string        // REJECT rule-set names, in order
	On      map[string]bool // sanctioned, irdomains, ircidr
}

func Conf(d ConfData) ([]byte, error) {
	var b bytes.Buffer
	err := tmpl.Execute(&b, d)
	return b.Bytes(), err
}
