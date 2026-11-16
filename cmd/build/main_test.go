package main

import "testing"

func TestSourceLink(t *testing.T) {
	repo := "https://github.com/o/r/"
	for in, want := range map[string]string{
		"file:///data/ir-ads.txt":   "https://github.com/o/r/blob/HEAD/data/ir-ads.txt",
		"https://example.com/a.txt": "https://example.com/a.txt",
	} {
		if got := sourceLink(repo, in); got != want {
			t.Errorf("sourceLink(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sourceLink("", "file:///data/x.txt"); got != "file:///data/x.txt" {
		t.Errorf("empty repo: got %q", got)
	}
}
