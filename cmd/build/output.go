// Writing outputs and the build summary.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
)

// syncDir makes dir contain exactly the given files (stale files are removed;
// subdirectories are left alone).
func syncDir(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if _, ok := files[e.Name()]; !ok && !e.IsDir() {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	for name, b := range files {
		if err := writeIfChanged(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	return nil
}

func writeIfChanged(path string, b []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return nil
	}
	return os.WriteFile(path, b, 0o644)
}

func printSummary(outs []outcome, cats []Category, stat func(string) (n, size int)) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "SOURCE\tCATEGORY\tSTATUS\tDOMAINS\tCIDRS\tNOTE\t")
	for _, o := range outs {
		note := ""
		if o.err != nil {
			note = o.err.Error()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t\n", o.src.Name, o.src.Category, o.status, len(o.res.Domains), len(o.res.CIDRs), note)
	}
	w.Flush()
	fmt.Println()
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "LIST\tACTION\tRULES\tSIZE KB\t")
	for _, c := range cats {
		n, size := stat(c.Name)
		if !c.Enabled {
			fmt.Fprintf(w, "%s\t%s\tdisabled\t\t\n", c.Name, c.Action)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%.1f\t\n", c.Name, c.Action, n, float64(size)/1024)
	}
	w.Flush()
}
