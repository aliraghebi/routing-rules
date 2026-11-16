package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGet(t *testing.T) {
	var hits, fails atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/flaky":
			if fails.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			w.Write([]byte("ok"))
		case "/etag":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			w.Write([]byte("cached body"))
		case "/big":
			w.Write([]byte(strings.Repeat("x", 100)))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	newF := func(dir string) *Fetcher {
		return &Fetcher{Client: srv.Client(), CacheDir: dir, UA: "t", MaxBytes: 50, Retries: 3, Backoff: time.Millisecond}
	}
	ctx := context.Background()
	dir := t.TempDir()

	if b, err := newF(dir).Get(ctx, srv.URL+"/flaky", 0); err != nil || string(b) != "ok" {
		t.Fatalf("flaky: %q %v", b, err)
	}
	if _, err := newF(dir).Get(ctx, srv.URL+"/big", 0); err == nil {
		t.Fatal("big: expected size cap error")
	}
	hits.Store(0)
	if _, err := newF(dir).Get(ctx, srv.URL+"/missing", 0); err == nil || hits.Load() != 1 {
		t.Fatalf("404 must fail without retry: %v hits=%d", err, hits.Load())
	}
	if b, _ := newF(dir).Get(ctx, srv.URL+"/etag", 0); string(b) != "cached body" {
		t.Fatalf("etag first: %q", b)
	}
	// New fetcher (no memo): server answers 304, body must come from disk.
	if b, err := newF(dir).Get(ctx, srv.URL+"/etag", 0); err != nil || string(b) != "cached body" {
		t.Fatalf("etag 304: %q %v", b, err)
	}
	if _, err := newF(dir).Get(ctx, srv.URL+"/missing?key=SECRET", 0); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error must not leak url: %v", err)
	}
}
