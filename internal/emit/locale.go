package emit

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

//go:embed locales/*.json
var localeFiles embed.FS

// Locale translates generated docs text. Keys are the English source strings
// (format strings for Tf); English needs no file and returns keys unchanged.
type Locale struct {
	Lang    string
	strings map[string]string
	mu      sync.Mutex
	missing map[string]bool
}

// LoadLocale loads locales/<lang>.json; "en" is the identity locale.
func LoadLocale(lang string) (*Locale, error) {
	l := &Locale{Lang: lang, strings: map[string]string{}, missing: map[string]bool{}}
	if lang == "en" {
		return l, nil
	}
	b, err := localeFiles.ReadFile("locales/" + lang + ".json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &l.strings); err != nil {
		return nil, fmt.Errorf("locales/%s.json: %w", lang, err)
	}
	return l, nil
}

// T returns the translation of s, or s itself (recorded as missing).
func (l *Locale) T(s string) string {
	if l.Lang == "en" {
		return s
	}
	if t, ok := l.strings[s]; ok {
		return t
	}
	l.mu.Lock()
	l.missing[s] = true
	l.mu.Unlock()
	return s
}

// Tf translates a format string, then formats it.
func (l *Locale) Tf(format string, args ...any) string {
	return fmt.Sprintf(l.T(format), args...)
}

// Missing lists keys that had no translation, sorted.
func (l *Locale) Missing() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.missing))
	for k := range l.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
