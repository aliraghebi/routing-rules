package emit

import (
	"bytes"
	"strings"
)

// Module renders a Shadowrocket / Surge module (.sgmodule) from a rendered
// Shadowrocket config: its [Rule] section without the final catch-all, so the
// rules sit on top of the user's own config, which keeps its servers and FINAL.
func Module(conf []byte) []byte {
	var b bytes.Buffer
	b.WriteString("#!name=Routing Rules\n")
	b.WriteString("#!desc=Blocks ads, trackers and malware; Iranian sites direct; sites that block Iranian IPs through the proxy. Updated daily.\n")
	b.WriteString("\n[Rule]\n")
	in := false
	for _, line := range strings.Split(string(conf), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "["):
			in = t == "[Rule]"
		case in && t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "FINAL,"):
			b.WriteString(t + "\n")
		}
	}
	return b.Bytes()
}
