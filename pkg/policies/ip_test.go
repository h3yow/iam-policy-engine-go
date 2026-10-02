package policies

import "testing"

func TestParseNetblockAndContains(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		// ---- IPv4 prefix boundaries ----
		{"v4 inside", "10.1.2.0/24", "10.1.2.50", true},
		{"v4 network address is in range", "10.1.2.0/24", "10.1.2.0", true},
		{"v4 broadcast address is in range", "10.1.2.0/24", "10.1.2.255", true},
		{"v4 just below prefix", "10.1.2.0/24", "10.1.1.255", false},
		{"v4 just above prefix", "10.1.2.0/24", "10.1.3.0", false},
		{"v4 /30 lower boundary", "192.0.2.4/30", "192.0.2.4", true},
		{"v4 /30 upper boundary", "192.0.2.4/30", "192.0.2.7", true},
		{"v4 /30 outside", "192.0.2.4/30", "192.0.2.8", false},
		// ---- bare IPv4 host ----
		{"v4 bare host equal", "172.16.0.1", "172.16.0.1", true},
		{"v4 bare host different", "172.16.0.1", "172.16.0.2", false},
		// ---- IPv6 ----
		{"v6 inside", "2001:db8::/32", "2001:db8:1234::1", true},
		{"v6 network address", "2001:db8::/32", "2001:db8::", true},
		{"v6 last address of prefix", "2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"v6 just below prefix", "2001:db8::/32", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"v6 just above prefix", "2001:db8::/32", "2001:db9::", false},
		{"v6 /128 bare form", "2001:db8::1", "2001:db8::1", true},
		// ---- family boundaries ----
		{"v4 netblock does not match v6", "10.0.0.0/8", "2001:db8::1", false},
		{"v6 netblock does not match v4", "2001:db8::/32", "10.1.2.3", false},
		{"v4-mapped v6 address matches v4 prefix", "10.1.2.0/24", "::ffff:10.1.2.5", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rng, err := parseNetblock(c.cidr)
			if err != nil {
				t.Fatalf("parseNetblock(%q): %v", c.cidr, err)
			}
			ip, err := parseAddress(c.ip)
			if err != nil {
				t.Fatalf("parseAddress(%q): %v", c.ip, err)
			}
			if got := rng.contains(ip); got != c.want {
				t.Fatalf("contains(%s in %s) = %v, want %v", c.ip, c.cidr, got, c.want)
			}
		})
	}
}

func TestParseNetblockErrors(t *testing.T) {
	bad := []string{"", "   ", "not-an-ip", "10.1.2.0/99", "10.1.2/24", "2001:db8::/200", "10.1.2.0/"}
	for _, s := range bad {
		if _, err := parseNetblock(s); err == nil {
			t.Fatalf("parseNetblock(%q) expected error", s)
		}
	}
	badAddr := []string{"", "999.1.1.1", "10.1.2", "2001:db8:::1"}
	for _, s := range badAddr {
		if _, err := parseAddress(s); err == nil {
			t.Fatalf("parseAddress(%q) expected error", s)
		}
	}
}
