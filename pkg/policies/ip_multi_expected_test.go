package policies

import "testing"

// ipClause runs one IpAddress-family clause against a single-key context and
// returns the clause outcome.
func ipClause(t *testing.T, op, actual string, expected []Value) (bool, ConditionReason) {
	t.Helper()
	ctx := map[string]Value{}
	if actual != "" {
		ctx["sourceIp"] = StringV(actual)
	}
	return evalOne(t, op, "sourceIp", expected, ctx)
}

// TestIpMultiExpectedInvalidMemberOrderIndependent pins the semantics when one
// condition key lists several expected networks and one of them is malformed
// (prefix length out of range, bad address literal, ...).
//
// The conclusion must be the SAME no matter where the bad member sits in the
// list: fail-closed with CondInvalidValue. A legal member that happens to match
// the request must never make the engine overlook a typo in another member.
func TestIpMultiExpectedInvalidMemberOrderIndependent(t *testing.T) {
	// Order A: the legal, matching member first, malformed members after it.
	orderMatchFirst := []Value{
		StringV("10.0.0.0/8"),  // legal and contains 10.0.0.7
		StringV("10.0.0.0/33"), // prefix length out of range
		StringV("10.0.0.256"),  // bad address literal
	}
	// Order B: same members, malformed first, matching member last.
	orderMatchLast := []Value{
		StringV("10.0.0.256"),
		StringV("10.0.0.0/33"),
		StringV("10.0.0.0/8"),
	}

	ctx := map[string]Value{"sourceIp": StringV("10.0.0.7")}

	for _, op := range []string{"IpAddress", "NotIpAddress"} {
		okA, reasonA := evalOne(t, op, "sourceIp", orderMatchFirst, ctx)
		t.Logf("CLAUSE op=%s actual=%v order=match-first -> ok=%v reason=%s", op, ctx["sourceIp"], okA, reasonA)
		okB, reasonB := evalOne(t, op, "sourceIp", orderMatchLast, ctx)
		t.Logf("CLAUSE op=%s actual=%v order=match-last  -> ok=%v reason=%s", op, ctx["sourceIp"], okB, reasonB)

		if okA || reasonA != CondInvalidValue {
			t.Fatalf("%s match-first: got ok=%v reason=%s, want ok=false reason=%s",
				op, okA, reasonA, CondInvalidValue)
		}
		if okB || reasonB != CondInvalidValue {
			t.Fatalf("%s match-last: got ok=%v reason=%s, want ok=false reason=%s",
				op, okB, reasonB, CondInvalidValue)
		}
	}
}

// TestIpMultiExpectedInvalidMemberNegatedOutside covers the case where the
// legal member does NOT contain the actual address. A negated clause with a
// typo anywhere in the exclusion set must fail as CondInvalidValue in both
// list orders — it must neither pass vacuously nor drift to did_not_match.
func TestIpMultiExpectedInvalidMemberNegatedOutside(t *testing.T) {
	matchFirst := []Value{StringV("10.0.0.0/8"), StringV("2001:db8::/129")}
	matchLast := []Value{StringV("2001:db8::/129"), StringV("10.0.0.0/8")}

	for _, op := range []string{"IpAddress", "NotIpAddress"} {
		for _, order := range []struct {
			tag string
			ex  []Value
		}{{"legal-first", matchFirst}, {"illegal-first", matchLast}} {
			ok, reason := ipClause(t, op, "8.8.8.8", order.ex)
			t.Logf("CLAUSE op=%s actual=%q expected-order=%s -> ok=%v reason=%s",
				op, "8.8.8.8", order.tag, ok, reason)
			if ok || reason != CondInvalidValue {
				t.Fatalf("%s %s: got ok=%v reason=%s, want ok=false reason=%s",
					op, order.tag, ok, reason, CondInvalidValue)
			}
		}
	}
}

// TestIpMultiExpectedInvalidMemberMultiActual makes sure a malformed expected
// member is detected no matter which actual values are evaluated against it,
// and regardless of the order on either side.
func TestIpMultiExpectedInvalidMemberMultiActual(t *testing.T) {
	matchFirst := []Value{StringV("10.0.0.0/8"), StringV("not-a-cidr")}
	matchLast := []Value{StringV("not-a-cidr"), StringV("10.0.0.0/8")}
	cases := []struct {
		tag string
		got Value
	}{
		{"single actual inside", StringV("10.0.0.7")},
		{"actual list, one inside", ListV(StringV("8.8.8.8"), StringV("10.0.0.9"))},
		{"actual list, all outside", ListV(StringV("8.8.8.8"), StringV("1.1.1.1"))},
	}
	for _, c := range cases {
		ctx := map[string]Value{"sourceIp": c.got}
		for _, op := range []string{"IpAddress", "NotIpAddress"} {
			for _, ex := range []struct {
				tag string
				v   []Value
			}{{"legal-first", matchFirst}, {"illegal-first", matchLast}} {
				ok, reason := evalOne(t, op, "sourceIp", ex.v, ctx)
				t.Logf("CLAUSE op=%s actual=%v expected-order=%s -> ok=%v reason=%s",
					op, c.got, ex.tag, ok, reason)
				if ok || reason != CondInvalidValue {
					t.Fatalf("%s/%s/%s: got ok=%v reason=%s, want ok=false reason=%s",
						c.tag, op, ex.tag, ok, reason, CondInvalidValue)
				}
			}
		}
	}
}

// TestIpMultiExpectedAllLegalOrderStable checks that lists WITHOUT malformed
// members keep conclusions identical across permutations, for both positive
// and negated operators.
func TestIpMultiExpectedAllLegalOrderStable(t *testing.T) {
	orderA := []Value{StringV("10.0.0.0/8"), StringV("2001:db8::/32"), StringV("192.168.1.1")}
	orderB := []Value{StringV("192.168.1.1"), StringV("10.0.0.0/8"), StringV("2001:db8::/32")}

	cases := []struct {
		name   string
		op     string
		actual string
		wantOK bool
		reason ConditionReason
	}{
		{"positive hits a member", "IpAddress", "10.0.0.7", true, CondOK},
		{"positive hits bare-address member", "IpAddress", "192.168.1.1", true, CondOK},
		{"positive hits no member", "IpAddress", "8.8.8.8", false, CondNoMatch},
		{"negated one member contains actual", "NotIpAddress", "10.0.0.7", false, CondNoMatch},
		{"negated all members miss actual", "NotIpAddress", "8.8.8.8", true, CondOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			okA, rA := ipClause(t, c.op, c.actual, orderA)
			okB, rB := ipClause(t, c.op, c.actual, orderB)
			t.Logf("CLAUSE %s op=%s actual=%q orderA -> ok=%v reason=%s", c.name, c.op, c.actual, okA, rA)
			t.Logf("CLAUSE %s op=%s actual=%q orderB -> ok=%v reason=%s", c.name, c.op, c.actual, okB, rB)
			if okA != c.wantOK || rA != c.reason {
				t.Fatalf("orderA: got ok=%v reason=%s, want ok=%v reason=%s", okA, rA, c.wantOK, c.reason)
			}
			if okA != okB || rA != rB {
				t.Fatalf("conclusion drifted across list permutation: %v/%s vs %v/%s", okA, rA, okB, rB)
			}
		})
	}
}

// TestIpBoundariesRemainStableAndDistinguishable pins the empty-value-set,
// missing-key and ordinary no-match boundaries for the IP operators. These
// outcomes must stay stable and mutually distinguishable (and unchanged from
// previous behavior).
func TestIpBoundariesRemainStableAndDistinguishable(t *testing.T) {
	emptyActual := map[string]Value{"sourceIp": ListV()}
	noKey := map[string]Value{}

	// Positive operator over an empty actual set -> empty_value_set.
	ok, reason := evalOne(t, "IpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")}, emptyActual)
	t.Logf("CLAUSE IpAddress empty-actual-set -> ok=%v reason=%s", ok, reason)
	if ok || reason != CondEmptyValueSet {
		t.Fatalf("empty actual + IpAddress: got ok=%v reason=%s", ok, reason)
	}
	// Negated operator over an empty actual set -> vacuously satisfied.
	ok, reason = evalOne(t, "NotIpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")}, emptyActual)
	t.Logf("CLAUSE NotIpAddress empty-actual-set -> ok=%v reason=%s", ok, reason)
	if !ok || reason != CondOK {
		t.Fatalf("empty actual + NotIpAddress: got ok=%v reason=%s, want true/%s", ok, reason, CondOK)
	}
	// Missing key fails both forms with key_missing (fail-closed).
	for _, op := range []string{"IpAddress", "NotIpAddress"} {
		ok, reason = evalOne(t, op, "sourceIp", []Value{StringV("10.0.0.0/8")}, noKey)
		t.Logf("CLAUSE %s missing-key -> ok=%v reason=%s", op, ok, reason)
		if ok || reason != CondKeyMissing {
			t.Fatalf("%s missing key: got ok=%v reason=%s, want false/%s", op, ok, reason, CondKeyMissing)
		}
	}
	// IfExists keeps tolerating a missing key for both forms.
	for _, op := range []string{"IpAddressIfExists", "NotIpAddressIfExists"} {
		ok, reason = evalOne(t, op, "sourceIp", []Value{StringV("10.0.0.0/8")}, noKey)
		t.Logf("CLAUSE %s missing-key -> ok=%v reason=%s", op, ok, reason)
		if !ok || reason != CondOK {
			t.Fatalf("%s missing key: got ok=%v reason=%s, want true/%s", op, ok, reason, CondOK)
		}
	}
	// An empty EXPECTED list is an ordinary non-match, distinct from the
	// invalid-value and empty-actual outcomes.
	ok, reason = evalOne(t, "IpAddress", "sourceIp", nil,
		map[string]Value{"sourceIp": StringV("10.0.0.1")})
	t.Logf("CLAUSE IpAddress empty-expected-list -> ok=%v reason=%s", ok, reason)
	if ok || reason != CondNoMatch {
		t.Fatalf("empty expected list: got ok=%v reason=%s, want false/%s", ok, reason, CondNoMatch)
	}
}

// TestIpSingleValueUnchanged is a focused regression guard for the
// single-actual/single-expected usages that must remain byte-identical in
// conclusion to the pre-fix behavior.
func TestIpSingleValueUnchanged(t *testing.T) {
	cases := []struct {
		name   string
		op     string
		actual string
		exp    string
		wantOK bool
		reason ConditionReason
	}{
		{"single v4 hit", "IpAddress", "10.0.0.7", "10.0.0.0/8", true, CondOK},
		{"single v4 miss", "IpAddress", "8.8.8.8", "10.0.0.0/8", false, CondNoMatch},
		{"single invalid cidr", "IpAddress", "10.0.0.7", "10.0.0.0/33", false, CondInvalidValue},
		{"single not-ip outside", "NotIpAddress", "8.8.8.8", "10.0.0.0/8", true, CondOK},
		{"single not-ip inside", "NotIpAddress", "10.0.0.7", "10.0.0.0/8", false, CondNoMatch},
		{"single not-ip invalid", "NotIpAddress", "10.0.0.7", "999.1.1.1/8", false, CondInvalidValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := ipClause(t, c.op, c.actual, []Value{StringV(c.exp)})
			t.Logf("CLAUSE op=%s actual=%q expected=%q -> ok=%v reason=%s", c.op, c.actual, c.exp, ok, reason)
			if ok != c.wantOK || reason != c.reason {
				t.Fatalf("got ok=%v reason=%s, want ok=%v reason=%s", ok, reason, c.wantOK, c.reason)
			}
		})
	}
}
