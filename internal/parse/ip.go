package parse

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/netip"
	"strings"
)

// U128 is an address as a 128-bit integer (IPv4 uses only Lo).
type U128 struct{ Hi, Lo uint64 }

func AddrToU128(a netip.Addr) U128 {
	if a.Is4() {
		b := a.As4()
		return U128{0, uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])}
	}
	b := a.As16()
	var x U128
	for i := 0; i < 8; i++ {
		x.Hi = x.Hi<<8 | uint64(b[i])
		x.Lo = x.Lo<<8 | uint64(b[i+8])
	}
	return x
}

func U128ToAddr(x U128, v4 bool) netip.Addr {
	if v4 {
		v := uint32(x.Lo)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(x.Hi >> (8 * i))
		b[15-i] = byte(x.Lo >> (8 * i))
	}
	return netip.AddrFrom16(b)
}

func (x U128) Cmp(y U128) int {
	switch {
	case x.Hi < y.Hi:
		return -1
	case x.Hi > y.Hi:
		return 1
	case x.Lo < y.Lo:
		return -1
	case x.Lo > y.Lo:
		return 1
	}
	return 0
}

func (x U128) Add1() U128 {
	lo, c := bits.Add64(x.Lo, 1, 0)
	return U128{x.Hi + c, lo}
}

func (x U128) Sub(y U128) U128 {
	lo, b := bits.Sub64(x.Lo, y.Lo, 0)
	return U128{x.Hi - y.Hi - b, lo}
}

func (x U128) trailingZeros() int {
	if x.Lo != 0 {
		return bits.TrailingZeros64(x.Lo)
	}
	if x.Hi != 0 {
		return 64 + bits.TrailingZeros64(x.Hi)
	}
	return 128
}

func (x U128) bitLen() int {
	if x.Hi != 0 {
		return 64 + bits.Len64(x.Hi)
	}
	return bits.Len64(x.Lo)
}

// addBlock returns x + 2^n.
func (x U128) addBlock(n int) U128 {
	if n >= 64 {
		return U128{x.Hi + 1<<(n-64), x.Lo}
	}
	lo, c := bits.Add64(x.Lo, 1<<n, 0)
	return U128{x.Hi + c, lo}
}

// RangeToPrefixes returns the minimal CIDR cover of [a, b] (same family).
func RangeToPrefixes(a, b netip.Addr) []netip.Prefix {
	a, b = a.Unmap(), b.Unmap()
	if a.Is4() != b.Is4() || b.Less(a) {
		return nil
	}
	v4 := a.Is4()
	width := 128
	if v4 {
		width = 32
	}
	lo, hi := AddrToU128(a), AddrToU128(b)
	var out []netip.Prefix
	for {
		size := lo.trailingZeros()
		if size > width {
			size = width
		}
		// shrink block until lo + 2^size - 1 <= hi
		if count := hi.Sub(lo).Add1(); count != (U128{}) { // zero = 2^128, no shrink needed
			if l := count.bitLen() - 1; l < size {
				size = l
			}
		}
		out = append(out, netip.PrefixFrom(U128ToAddr(lo, v4), width-size))
		if size == width {
			return out // whole address space
		}
		next := lo.addBlock(size)
		last := next.Sub(U128{0, 1})
		if last.Cmp(hi) >= 0 {
			return out
		}
		lo = next
	}
}

// JSON walks any JSON document and collects every string that parses as a
// CIDR or range. Objects that have a Filter key with a different value are
// skipped together with their children (e.g. AWS service != CLOUDFRONT).
func JSON(data []byte, opt Options) (Result, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return Result{}, err
	}
	var r Result
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, want := range opt.Filter {
				if got, ok := t[k].(string); ok && got != want {
					return
				}
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		case string:
			if strings.ContainsAny(t, "/-") {
				r.CIDRs = append(r.CIDRs, ParsePrefixish(t)...)
			}
		}
	}
	walk(v)
	return r, nil
}

// zipFiles returns the files in a zip (or the raw body as one file if it is not a zip).
func zipFiles(data []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return map[string][]byte{"": data}, nil
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 512<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[f.Name] = b
	}
	return out, nil
}

// MaxMind parses a GeoLite2-Country-CSV zip and returns networks whose
// geoname_id (falling back to registered_country_geoname_id) is opt.Country.
func MaxMind(data []byte, opt Options) (Result, error) {
	files, err := zipFiles(data)
	if err != nil {
		return Result{}, err
	}
	ids := map[string]bool{}
	for name, b := range files {
		if !strings.Contains(name, "Locations-en") {
			continue
		}
		recs, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", name, err)
		}
		col := index(recs, "country_iso_code")
		for _, rec := range recs[1:] {
			if col >= 0 && col < len(rec) && strings.EqualFold(rec[col], opt.Country) {
				ids[rec[0]] = true
			}
		}
	}
	if len(ids) == 0 {
		return Result{}, fmt.Errorf("maxmind: country %q not found in locations", opt.Country)
	}
	var r Result
	for name, b := range files {
		if !strings.Contains(name, "Blocks-IPv") {
			continue
		}
		recs, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", name, err)
		}
		gid, rid := index(recs, "geoname_id"), index(recs, "registered_country_geoname_id")
		for _, rec := range recs[1:] {
			id := rec[gid]
			if id == "" && rid >= 0 {
				id = rec[rid]
			}
			if ids[id] {
				r.CIDRs = append(r.CIDRs, ParsePrefixish(rec[0])...)
			}
		}
	}
	return r, nil
}

func index(recs [][]string, col string) int {
	if len(recs) == 0 {
		return -1
	}
	for i, h := range recs[0] {
		if h == col {
			return i
		}
	}
	return -1
}

var mapped = netip.MustParsePrefix("::ffff:0:0/96")

// IP2Location parses an IP2Location LITE DB1 CSV (IPv4 or IPv6 edition, zipped
// or raw): "ip_from","ip_to","country_code","country_name" with decimal integers.
func IP2Location(data []byte, opt Options) (Result, error) {
	files, err := zipFiles(data)
	if err != nil {
		return Result{}, err
	}
	var r Result
	for _, b := range files {
		cr := csv.NewReader(bytes.NewReader(b))
		cr.FieldsPerRecord = -1
		for {
			rec, err := cr.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return Result{}, err
			}
			if len(rec) < 3 || !strings.EqualFold(rec[2], opt.Country) {
				continue
			}
			a, ok1 := decAddr(rec[0])
			b, ok2 := decAddr(rec[1])
			if !ok1 || !ok2 {
				continue
			}
			if mapped.Contains(a) && mapped.Contains(b) {
				a, b = a.Unmap(), b.Unmap()
			}
			r.CIDRs = append(r.CIDRs, RangeToPrefixes(a, b)...)
		}
	}
	return r, nil
}

func decAddr(s string) (netip.Addr, bool) {
	n, ok := new(big.Int).SetString(strings.TrimSpace(s), 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 128 {
		return netip.Addr{}, false
	}
	if n.IsUint64() && n.Uint64() <= 0xffffffff {
		// IPv4 edition stores plain 32-bit integers.
		v := uint32(n.Uint64())
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
	}
	var b [16]byte
	n.FillBytes(b[:])
	return netip.AddrFrom16(b), true
}
