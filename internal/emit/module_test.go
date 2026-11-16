package emit

import (
	"strings"
	"testing"
)

func TestModule(t *testing.T) {
	conf := "[General]\nipv6 = true\n\n[Rule]\nRULE-SET,https://x/ads.list,REJECT\nGEOIP,IR,DIRECT\nFINAL,PROXY\n\n[Host]\nlocalhost = 127.0.0.1\n"
	got := string(Module([]byte(conf)))
	if !strings.HasPrefix(got, "#!name=Routing Rules\n") || !strings.HasSuffix(got, "[Rule]\nRULE-SET,https://x/ads.list,REJECT\nGEOIP,IR,DIRECT\n") {
		t.Fatalf("module:\n%s", got)
	}
	if strings.Contains(got, "FINAL") || strings.Contains(got, "ipv6") || strings.Contains(got, "localhost") {
		t.Fatalf("module must hold only the rules, without FINAL:\n%s", got)
	}
}
