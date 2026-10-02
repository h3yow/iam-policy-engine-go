package policies

import "net/netip"

// ipInExpected implements the IpAddress / NotIpAddress comparison for one
// (actual, expected) pair.
//
// The actual value must be a literal IPv4 or IPv6 address. The expected value
// may be a single address or a CIDR prefix (IPv4 or IPv6); a bare address is
// treated as a host prefix (/32 or /128). Containment is inclusive of the
// network and broadcast boundary addresses: an address falls inside the
// prefix iff every prefix bit matches, so boundary addresses are classified
// correctly.
//
// valid == false when either side is malformed; the caller surfaces this as
// CondInvalidValue so a typo can never silently pass or fail a clause.
func ipInExpected(got, expected Value) (matched, valid bool) {
	addr, err := netip.ParseAddr(got.Str)
	if err != nil {
		return false, false
	}
	// A zone-holding IPv6 address (fe80::1%eth0) is not comparable to a
	// prefix; treat it as malformed rather than guessing.
	if addr.Zone() != "" {
		return false, false
	}

	prefix, err := netip.ParsePrefix(expected.Str)
	if err == nil {
		return prefix.Contains(addr), true
	}
	expAddr, err := netip.ParseAddr(expected.Str)
	if err != nil {
		return false, false
	}
	if expAddr.Zone() != "" {
		return false, false
	}
	return addr == expAddr, true
}
