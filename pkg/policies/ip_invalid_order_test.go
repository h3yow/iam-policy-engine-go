package policies

import "testing"

// TestIpInvalidExpectedOrderIndependent pins the fail-closed semantics for a
// multi-valued expected list that mixes a valid, matching entry with an
// invalid one: the outcome (and its reason) must be identical no matter how
// the entries are ordered. A typo in one entry must never be silently
// ignored just because another entry matched.
func TestIpInvalidExpectedOrderIndependent(t *testing.T) {
	validHit := StringV("10.0.0.0/8")   // matches actual 10.1.2.3
	validMiss := StringV("192.168.0.0/16") // does not match actual 10.1.2.3
	badPrefix := StringV("10.0.0.0/33")   // prefix length out of range
	badAddr := StringV("10.0.0.256")      // not an address at all
	actual := StringV("10.1.2.3")

	cases := []struct {
		name     string
		op       string
		expected []Value
		ok       bool
		reason   ConditionReason
	}{
		// ---- positive operator: valid hit + invalid entry, both orders ----
		{"ip valid-hit-then-invalid", "IpAddress", []Value{validHit, badPrefix}, false, CondInvalidValue},
		{"ip invalid-then-valid-hit", "IpAddress", []Value{badPrefix, validHit}, false, CondInvalidValue},
		{"ip valid-hit-then-invalid-addr", "IpAddress", []Value{validHit, badAddr}, false, CondInvalidValue},
		{"ip invalid-addr-then-valid-hit", "IpAddress", []Value{badAddr, validHit}, false, CondInvalidValue},

		// ---- positive operator: valid miss + invalid entry, both orders ----
		{"ip valid-miss-then-invalid", "IpAddress", []Value{validMiss, badPrefix}, false, CondInvalidValue},
		{"ip invalid-then-valid-miss", "IpAddress", []Value{badPrefix, validMiss}, false, CondInvalidValue},

		// ---- negated operator: excluded hit + invalid entry, both orders ----
		{"not-ip valid-hit-then-invalid", "NotIpAddress", []Value{validHit, badPrefix}, false, CondInvalidValue},
		{"not-ip invalid-then-valid-hit", "NotIpAddress", []Value{badPrefix, validHit}, false, CondInvalidValue},

		// ---- negated operator: non-matching valid + invalid entry, both orders ----
		{"not-ip valid-miss-then-invalid", "NotIpAddress", []Value{validMiss, badPrefix}, false, CondInvalidValue},
		{"not-ip invalid-then-valid-miss", "NotIpAddress", []Value{badPrefix, validMiss}, false, CondInvalidValue},

		// ---- several invalid entries among valid ones ----
		{"ip invalid-sandwich", "IpAddress", []Value{badPrefix, validHit, badAddr}, false, CondInvalidValue},
		{"not-ip invalid-sandwich", "NotIpAddress", []Value{badAddr, validMiss, badPrefix}, false, CondInvalidValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := evalOne(t, c.op, "sourceIp", c.expected, map[string]Value{"sourceIp": actual})
			t.Logf("CLAUSE op=%s actual=%v expected=%v -> ok=%v reason=%s", c.op, actual, c.expected, ok, reason)
			if ok != c.ok || reason != c.reason {
				t.Fatalf("got ok=%v reason=%s, want ok=%v reason=%s", ok, reason, c.ok, c.reason)
			}
		})
	}
}

// TestIpBoundaryOutcomesStable covers the empty-set / missing-key boundaries
// for the network-location operators: each boundary must produce its own
// stable, distinguishable outcome that does not drift with value order.
func TestIpBoundaryOutcomesStable(t *testing.T) {
	// Empty expected list: nothing to compare against -> stable no-match,
	// distinct from invalid-value and missing-key outcomes.
	t.Run("empty expected set positive", func(t *testing.T) {
		ok, reason := evalOne(t, "IpAddress", "sourceIp", []Value{}, map[string]Value{"sourceIp": StringV("10.1.2.3")})
		t.Logf("CLAUSE op=IpAddress expected=[] -> ok=%v reason=%s", ok, reason)
		if ok || reason != CondNoMatch {
			t.Fatalf("got ok=%v reason=%s, want ok=false reason=%s", ok, reason, CondNoMatch)
		}
	})
	t.Run("empty expected set negated", func(t *testing.T) {
		ok, reason := evalOne(t, "NotIpAddress", "sourceIp", []Value{}, map[string]Value{"sourceIp": StringV("10.1.2.3")})
		t.Logf("CLAUSE op=NotIpAddress expected=[] -> ok=%v reason=%s", ok, reason)
		if ok || reason != CondNoMatch {
			t.Fatalf("got ok=%v reason=%s, want ok=false reason=%s", ok, reason, CondNoMatch)
		}
	})

	// Empty actual value set: positive fails with its own reason, negated
	// passes vacuously; both differ from a missing key.
	t.Run("empty actual set positive", func(t *testing.T) {
		ok, reason := evalOne(t, "IpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")},
			map[string]Value{"sourceIp": ListV()})
		t.Logf("CLAUSE op=IpAddress actual=[] -> ok=%v reason=%s", ok, reason)
		if ok || reason != CondEmptyValueSet {
			t.Fatalf("got ok=%v reason=%s, want ok=false reason=%s", ok, reason, CondEmptyValueSet)
		}
	})
	t.Run("empty actual set negated", func(t *testing.T) {
		ok, reason := evalOne(t, "NotIpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")},
			map[string]Value{"sourceIp": ListV()})
		t.Logf("CLAUSE op=NotIpAddress actual=[] -> ok=%v reason=%s", ok, reason)
		if !ok || reason != CondOK {
			t.Fatalf("got ok=%v reason=%s, want ok=true reason=%s", ok, reason, CondOK)
		}
	})

	// Missing key: fail-closed with its own reason for both polarities.
	t.Run("missing key positive", func(t *testing.T) {
		ok, reason := evalOne(t, "IpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")}, map[string]Value{})
		t.Logf("CLAUSE op=IpAddress key absent -> ok=%v reason=%s", ok, reason)
		if ok || reason != CondKeyMissing {
			t.Fatalf("got ok=%v reason=%s, want ok=false reason=%s", ok, reason, CondKeyMissing)
		}
	})
	t.Run("missing key negated", func(t *testing.T) {
		ok, reason := evalOne(t, "NotIpAddress", "sourceIp", []Value{StringV("10.0.0.0/8")}, map[string]Value{})
		t.Logf("CLAUSE op=NotIpAddress key absent -> ok=%v reason=%s", ok, reason)
		if ok || reason != CondKeyMissing {
			t.Fatalf("got ok=%v reason=%s, want ok=false reason=%s", ok, reason, CondKeyMissing)
		}
	})
}
