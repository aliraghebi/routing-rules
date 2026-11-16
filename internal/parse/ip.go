package parse

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"io"
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

// DBIP parses a DB-IP Lite country CSV ("start,end,country", optionally
// gzipped) and returns the ranges for opt.Country as CIDRs.
func DBIP(data []byte, opt Options) (Result, error) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return Result{}, err
		}
		if data, err = io.ReadAll(io.LimitReader(zr, 1<<30)); err != nil {
			return Result{}, err
		}
	}
	var r Result
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
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
		a, err1 := netip.ParseAddr(rec[0])
		b, err2 := netip.ParseAddr(rec[1])
		if err1 == nil && err2 == nil {
			r.CIDRs = append(r.CIDRs, RangeToPrefixes(a, b)...)
		}
	}
	return r, nil
}
