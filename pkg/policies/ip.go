package policies

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

// ipRange is an inclusive [start, end] interval of IP addresses of one family
// (4 bytes for IPv4, 16 bytes for IPv6). Working with an explicit integer-style
// interval instead of net.IPNet.Contains keeps the boundary semantics
// independent of the 4- vs 16-byte representations net.ParseIP may return:
// both the network address and the directed broadcast address of a prefix are
// considered inside the range.
type ipRange struct {
	start []byte
	end   []byte
}

var (
	// errInvalidAddress is returned for request-side values that are not valid
	// IP literals.
	errInvalidAddress = errors.New("invalid IP address")
	// errInvalidNetblock is returned for policy-side values that are neither
	// valid IP literals nor valid CIDR prefixes.
	errInvalidNetblock = errors.New("invalid IP netblock")
)

// parseNetblock parses one policy-side comparison value.
//
// Accepted forms are CIDR prefixes ("10.1.2.0/24", "2001:db8::/32") and bare
// addresses ("10.1.2.3", "2001:db8::1"), the latter meaning a host route
// (/32 for IPv4, /128 for IPv6). Whitespace around the literal is rejected
// rather than ignored, except that surrounding spaces are trimmed.
func parseNetblock(s string) (ipRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ipRange{}, errInvalidNetblock
	}
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return ipRange{}, errInvalidNetblock
		}
		mask := ipnet.Mask
		raw := ipnet.IP
		if len(mask) == net.IPv4len {
			raw = raw.To4()
		}
		if raw == nil || len(raw) != len(mask) {
			return ipRange{}, errInvalidNetblock
		}
		start := raw.Mask(mask) // network address
		end := make([]byte, len(start))
		for i := range start {
			end[i] = start[i] | ^mask[i]
		}
		return ipRange{start: append([]byte(nil), start...), end: end}, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ipRange{}, errInvalidNetblock
	}
	if v4 := ip.To4(); v4 != nil && strings.Contains(s, ".") {
		return ipRange{start: append([]byte(nil), v4...), end: append([]byte(nil), v4...)}, nil
	}
	v6 := ip.To16()
	return ipRange{start: append([]byte(nil), v6...), end: append([]byte(nil), v6...)}, nil
}

// parseAddress parses one request-side IP literal.
func parseAddress(s string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil, errInvalidAddress
	}
	return ip, nil
}

// contains reports whether ip falls inside the inclusive interval. Families
// must agree; an IPv4-mapped IPv6 address is accepted by IPv4 intervals.
func (r ipRange) contains(ip net.IP) bool {
	var b []byte
	if len(r.start) == net.IPv4len {
		b = ip.To4()
	} else {
		b = ip.To16()
	}
	if b == nil || len(b) != len(r.start) {
		return false
	}
	return bytes.Compare(b, r.start) >= 0 && bytes.Compare(b, r.end) <= 0
}
