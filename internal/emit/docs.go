package emit

import (
	"bytes"
	_ "embed"
	"text/template"
)

// DocRow is one published file.
type DocRow struct {
	Name, Desc, URL string
}

type DocSection struct {
	Title, Note string
	Rows        []DocRow
}

type URLDocs struct {
	RepoURL, BaseURL string
	Sections         []DocSection
}

// DocSource is one sources.yaml entry for the generated sources page.
type DocSource struct {
	Name, URL, Category, Format, License string
	Enabled                              bool
}

var (
	//go:embed templates/urls.md.tmpl
	urlsTmpl string
	//go:embed templates/sources.md.tmpl
	sourcesTmpl string

	urlsDoc    = template.Must(template.New("urls").Parse(urlsTmpl))
	sourcesDoc = template.Must(template.New("sources").Parse(sourcesTmpl))
)

func URLsPage(d URLDocs) ([]byte, error) {
	var b bytes.Buffer
	err := urlsDoc.Execute(&b, d)
	return b.Bytes(), err
}

func SourcesPage(s []DocSource) ([]byte, error) {
	var b bytes.Buffer
	err := sourcesDoc.Execute(&b, s)
	return b.Bytes(), err
}
