package emit

import (
	"bytes"
	"embed"
	"regexp"
	"strings"
	"text/template"
	"unicode"
)

// DocRow is one published file.
type DocRow struct {
	Name, Desc, URL string
}

type DocSection struct {
	ID          string // anchor, from the English title, so links work in every language
	Title, Note string
	Rows        []DocRow
}

// Slug turns a heading into the anchor MkDocs generates for it
// (Python-Markdown's default slugify).
func Slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r == ' ' || r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), " ")
	out = regexp.MustCompile(`[-\s]+`).ReplaceAllString(out, "-")
	return out
}

type URLDocs struct {
	RepoURL, BaseURL string
	Sections         []DocSection
}

// DocSource is one sources.yaml entry for the generated sources page.
type DocSource struct {
	Name, URL, Category, Format, License string
	Enabled                              bool
	Health                               string // localized status label
	Fetched, Changed                     string // YYYY-MM-DD or "—"
}

//go:embed templates/*.md.tmpl
var pageTemplates embed.FS

// page renders templates/<name>.md.tmpl, or <name>.<lang>.md.tmpl for a
// translated language.
func page(name, lang string, data any) ([]byte, error) {
	file := "templates/" + name + ".md.tmpl"
	if lang != "en" {
		file = "templates/" + name + "." + lang + ".md.tmpl"
	}
	src, err := pageTemplates.ReadFile(file)
	if err != nil {
		return nil, err
	}
	t, err := template.New(name).Parse(string(src))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, data)
	return b.Bytes(), err
}

func URLsPage(lang string, d URLDocs) ([]byte, error)        { return page("urls", lang, d) }
func SourcesPage(lang string, s []DocSource) ([]byte, error) { return page("sources", lang, s) }
