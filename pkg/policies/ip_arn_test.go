package policies

import "testing"

func TestIpAddressOperator(t *testing.T) {
	cases := []struct {
		name     string
		op       string
		actual   Value
		expected []Value
		ok       bool
		reason   ConditionReason
	}{
		// ---- IPv4 ----
		{"v4 inside cidr", "IpAddress", StringV("10.0.0.7"), []Value{StringV("10.0.0.0/8")}, true, CondOK},
		{"v4 network boundary is inside", "IpAddress", StringV("10.0.0.0"), []Value{StringV("10.0.0.0/24")}, true, CondOK},
		{"v4 broadcast boundary is inside", "IpAddress", StringV("10.0.0.255"), []Value{StringV("10.0.0.0/24")}, true, CondOK},
		{"v4 one past broadcast is outside", "IpAddress", StringV("10.0.1.0"), []Value{StringV("10.0.0.0/24")}, false, CondNoMatch},
		{"v4 one below network is outside", "IpAddress", StringV("9.255.255.255"), []Value{StringV("10.0.0.0/8")}, false, CondNoMatch},
		{"v4 bare address equals host", "IpAddress", StringV("192.168.1.1"), []Value{StringV("192.168.1.1")}, true, CondOK},
		{"v4 bare address differs", "IpAddress", StringV("192.168.1.2"), []Value{StringV("192.168.1.1")}, false, CondNoMatch},
		{"v4 /32 host prefix", "IpAddress", StringV("192.168.1.1"), []Value{StringV("192.168.1.1/32")}, true, CondOK},

		// ---- IPv6 ----
		{"v6 inside cidr", "IpAddress", StringV("2001:db8::1"), []Value{StringV("2001:db8::/32")}, true, CondOK},
		{"v6 boundary address is inside", "IpAddress", StringV("2001:db8::"), []Value{StringV("2001:db8::/32")}, true, CondOK},
		{"v6 outside cidr", "IpAddress", StringV("2001:db9::1"), []Value{StringV("2001:db8::/32")}, false, CondNoMatch},
		{"v6 bare address equals host", "IpAddress", StringV("::1"), []Value{StringV("::1")}, true, CondOK},
		{"v6 /128 host prefix", "IpAddress", StringV("2001:db8::5"), []Value{StringV("2001:db8::5/128")}, true, CondOK},

		// ---- mixed / malformed ----
		{"v4 actual against v6 prefix no match", "IpAddress", StringV("10.0.0.1"), []Value{StringV("2001:db8::/32")}, false, CondNoMatch},
		{"malformed actual ip", "IpAddress", StringV("999.1.2.3"), []Value{StringV("10.0.0.0/8")}, false, CondInvalidValue},
		{"non-ip actual string", "IpAddress", StringV("not-an-ip"), []Value{StringV("10.0.0.0/8")}, false, CondInvalidValue},
		{"malformed expected cidr", "IpAddress", StringV("10.0.0.1"), []Value{StringV("10.0.0.0/33")}, false, CondInvalidValue},
		{"malformed expected address", "IpAddress", StringV("10.0.0.1"), []Value{StringV("10.0.0.256")}, false, CondInvalidValue},
		{"zoned v6 actual rejected", "IpAddress", StringV("fe80::1%eth0"), []Value{StringV("fe80::/10")}, false, CondInvalidValue},

		// ---- negation (whole-set exclusion) ----
		{"not-ip outside cidr passes", "NotIpAddress", StringV("8.8.8.8"), []Value{StringV("10.0.0.0/8")}, true, CondOK},
		{"not-ip inside cidr fails", "NotIpAddress", StringV("10.1.2.3"), []Value{StringV("10.0.0.0/8")}, false, CondNoMatch},
		{"not-ip boundary address still excluded", "NotIpAddress", StringV("10.0.0.255"), []Value{StringV("10.0.0.0/24")}, false, CondNoMatch},
		{"not-ip multi-value one inside fails", "NotIpAddress",
			ListV(StringV("8.8.8.8"), StringV("10.0.0.9")), []Value{StringV("10.0.0.0/8")}, false, CondNoMatch},
		{"not-ip multi-value all outside passes", "NotIpAddress",
			ListV(StringV("8.8.8.8"), StringV("2001:db8::1")), []Value{StringV("10.0.0.0/8")}, true, CondOK},
		{"not-ip malformed actual is invalid not pass", "NotIpAddress", StringV("bogus"), []Value{StringV("10.0.0.0/8")}, false, CondInvalidValue},

		// ---- multi-value positive ----
		{"ip multi-value any inside passes", "IpAddress",
			ListV(StringV("8.8.8.8"), StringV("10.0.0.9")), []Value{StringV("10.0.0.0/8")}, true, CondOK},
		{"ip forallvalues one outside fails", "ForAllValues:IpAddress",
			ListV(StringV("10.0.0.9"), StringV("8.8.8.8")), []Value{StringV("10.0.0.0/8")}, false, CondNoMatch},
		{"ip forallvalues all inside passes", "ForAllValues:IpAddress",
			ListV(StringV("10.0.0.9"), StringV("10.0.0.10")), []Value{StringV("10.0.0.0/8")}, true, CondOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := evalOne(t, c.op, "sourceIp", c.expected, map[string]Value{"sourceIp": c.actual})
			t.Logf("CLAUSE op=%s actual=%v expected=%v -> ok=%v reason=%s", c.op, c.actual, c.expected, ok, reason)
			if ok != c.ok || reason != c.reason {
				t.Fatalf("got ok=%v reason=%s, want ok=%v reason=%s", ok, reason, c.ok, c.reason)
			}
		})
	}
}

func TestArnOperators(t *testing.T) {
	cases := []struct {
		name     string
		op       string
		actual   Value
		expected []Value
		ok       bool
		reason   ConditionReason
	}{
		{"arn exact match", "ArnLike", StringV("arn:aws:s3:::app/file"), []Value{StringV("arn:aws:s3:::app/file")}, true, CondOK},
		{"arn wildcard suffix", "ArnLike", StringV("arn:aws:s3:::app/dir/file"), []Value{StringV("arn:aws:s3:::app/*")}, true, CondOK},
		{"arn wildcard segment", "ArnLike", StringV("arn:aws:iam::123:user/alice"), []Value{StringV("arn:aws:iam::*:user/*")}, true, CondOK},
		{"arn single-char wildcard", "ArnLike", StringV("arn:aws:s3:::app-a"), []Value{StringV("arn:aws:s3:::app-?")}, true, CondOK},
		{"arn different service no match", "ArnLike", StringV("arn:aws:ec2:::i-1"), []Value{StringV("arn:aws:s3:::*")}, false, CondNoMatch},
		{"arn prefix must not over-match", "ArnLike", StringV("arn:aws:s3:::application/x"), []Value{StringV("arn:aws:s3:::app")}, false, CondNoMatch},

		{"arn-not-like outside passes", "ArnNotLike", StringV("arn:aws:s3:::public/x"), []Value{StringV("arn:aws:s3:::secret/*")}, true, CondOK},
		{"arn-not-like inside fails", "ArnNotLike", StringV("arn:aws:s3:::secret/x"), []Value{StringV("arn:aws:s3:::secret/*")}, false, CondNoMatch},
		{"arn-not-like multi-value one inside fails", "ArnNotLike",
			ListV(StringV("arn:aws:s3:::public/x"), StringV("arn:aws:s3:::secret/y")),
			[]Value{StringV("arn:aws:s3:::secret/*")}, false, CondNoMatch},
		{"arn-not-like multi-value all outside passes", "ArnNotLike",
			ListV(StringV("arn:aws:s3:::public/x"), StringV("arn:aws:s3:::public/y")),
			[]Value{StringV("arn:aws:s3:::secret/*")}, true, CondOK},
		{"arn forallvalues all match", "ForAllValues:ArnLike",
			ListV(StringV("arn:aws:s3:::app/a"), StringV("arn:aws:s3:::app/b")),
			[]Value{StringV("arn:aws:s3:::app/*")}, true, CondOK},
		{"arn forallvalues one misses", "ForAllValues:ArnLike",
			ListV(StringV("arn:aws:s3:::app/a"), StringV("arn:aws:s3:::other/b")),
			[]Value{StringV("arn:aws:s3:::app/*")}, false, CondNoMatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := evalOne(t, c.op, "resourceArn", c.expected, map[string]Value{"resourceArn": c.actual})
			t.Logf("CLAUSE op=%s actual=%v expected=%v -> ok=%v reason=%s", c.op, c.actual, c.expected, ok, reason)
			if ok != c.ok || reason != c.reason {
				t.Fatalf("got ok=%v reason=%s, want ok=%v reason=%s", ok, reason, c.ok, c.reason)
			}
		})
	}
}
