// Package fetch downloads sources with retries, a size cap and an
// ETag/Last-Modified disk cache.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Fetcher struct {
	Client   *http.Client
	CacheDir string // empty disables the disk cache
	UA       string
	MaxBytes int64
	Retries  int
	Backoff  time.Duration

	mu   sync.Mutex
	memo map[string][]byte
}

type meta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// statusError is returned for non-2xx/304 responses.
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("http status %d", e.code) }

func retryable(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code == 429 || se.code >= 500
	}
	return !errors.Is(err, errTooLarge)
}

var errTooLarge = errors.New("response exceeds size cap")

// Get returns the body of rawURL. maxBytes <= 0 uses the Fetcher default.
// Errors never contain the URL (it may carry a license key).
func (f *Fetcher) Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	f.mu.Lock()
	if b, ok := f.memo[rawURL]; ok {
		f.mu.Unlock()
		return b, nil
	}
	f.mu.Unlock()
	if maxBytes <= 0 {
		maxBytes = f.MaxBytes
	}
	var err error
	var b []byte
	for attempt := 0; attempt <= f.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(f.Backoff << (attempt - 1)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if b, err = f.once(ctx, rawURL, maxBytes); err == nil || !retryable(err) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if f.memo == nil {
		f.memo = map[string][]byte{}
	}
	f.memo[rawURL] = b
	f.mu.Unlock()
	return b, nil
}

func (f *Fetcher) paths(rawURL string) (body, metaPath string) {
	h := sha256.Sum256([]byte(rawURL))
	base := filepath.Join(f.CacheDir, "http", hex.EncodeToString(h[:16]))
	return base + ".body", base + ".meta"
}

func (f *Fetcher) once(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid url")
	}
	req.Header.Set("User-Agent", f.UA)
	var m meta
	bodyPath, metaPath := f.paths(rawURL)
	if f.CacheDir != "" {
		if mb, err := os.ReadFile(metaPath); err == nil {
			if _, err := os.Stat(bodyPath); err == nil && json.Unmarshal(mb, &m) == nil {
				if m.ETag != "" {
					req.Header.Set("If-None-Match", m.ETag)
				}
				if m.LastModified != "" {
					req.Header.Set("If-Modified-Since", m.LastModified)
				}
			}
		}
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL from the message
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && f.CacheDir != "" {
		return os.ReadFile(bodyPath)
	}
	if resp.StatusCode/100 != 2 {
		return nil, statusError{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, errTooLarge
	}
	if f.CacheDir != "" {
		m = meta{resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")}
		if m != (meta{}) {
			mb, _ := json.Marshal(m)
			if err := os.MkdirAll(filepath.Dir(bodyPath), 0o755); err == nil {
				// Body first: a meta file without its body is never trusted.
				if os.WriteFile(bodyPath, b, 0o644) == nil {
					_ = os.WriteFile(metaPath, mb, 0o644)
				}
			}
		}
	}
	return b, nil
}
