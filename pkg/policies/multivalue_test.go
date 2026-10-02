package policies

import "testing"

func clauseOK(t *testing.T, set ConditionSet, ctx map[string]Value, want bool, wantReason ConditionReason) {
	t.Helper()
	outs, ok := EvaluateConditions(set, ctx)
	for _, o := range outs {
		t.Logf("CLAUSE op=%s key=%s success=%v reason=%s detail=%q", o.Operator, o.Key, o.Success, o.Reason, o.Detail)
	}
	t.Logf("CONTEXT=%v  => ok=%v", ctx, ok)
	if ok != want {
		t.Fatalf("ok=%v want %v (outcomes=%+v)", ok, want, outs)
	}
	if !want {
		found := false
		for _, o := range outs {
			if o.Reason == wantReason {
				found = true
			}
		}
		if !found {
			t.Fatalf("want reason %q, got %+v", wantReason, outs)
		}
	}
}

func strs(ss ...string) Value {
	vs := make([]Value, 0, len(ss))
	for _, s := range ss {
		vs = append(vs, StringV(s))
	}
	return ListV(vs...)
}

func TestMultivaluedQuantifiers(t *testing.T) {
	t.Run("default positive is some-match, independent of count/order", func(t *testing.T) {
		set := setOf("StringEquals", "tag", StringV("prod"))
		clauseOK(t, set, map[string]Value{"tag": strs("dev", "prod")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "dev")}, true, CondOK) // same conclusion, other order
		clauseOK(t, set, map[string]Value{"tag": strs("dev", "qa")}, false, CondNoMatch)
		// single value keeps the old behavior
		clauseOK(t, set, map[string]Value{"tag": StringV("prod")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"tag": StringV("dev")}, false, CondNoMatch)
	})

	t.Run("default negation requires the WHOLE group disjoint", func(t *testing.T) {
		set := setOf("StringNotEquals", "tag", StringV("prod"))
		clauseOK(t, set, map[string]Value{"tag": strs("dev", "qa")}, true, CondOK)
		// one member in the exclusion set -> fail; the other value cannot rescue
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "dev")}, false, CondNoMatch)
		clauseOK(t, set, map[string]Value{"tag": strs("dev", "prod")}, false, CondNoMatch)
		clauseOK(t, set, map[string]Value{"tag": StringV("prod")}, false, CondNoMatch)
		clauseOK(t, set, map[string]Value{"tag": StringV("dev")}, true, CondOK)
	})

	t.Run("explicit ForAllValues positive", func(t *testing.T) {
		set := setOf("ForAllValues:StringEquals", "tag", StringV("prod"), StringV("qa"))
		// every actual value must hit some expected value
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "qa")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "prod")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "dev")}, false, CondNoMatch)
	})

	t.Run("explicit ForAnyValue negation", func(t *testing.T) {
		set := setOf("ForAnyValue:StringNotEquals", "tag", StringV("prod"))
		// at least one actual value must escape the exclusion set
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "dev")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "prod")}, false, CondNoMatch)
	})

	t.Run("ForAllValues negation equals disjoint-set default", func(t *testing.T) {
		set := setOf("ForAllValues:StringNotEquals", "tag", StringV("prod"))
		clauseOK(t, set, map[string]Value{"tag": strs("prod", "dev")}, false, CondNoMatch)
		clauseOK(t, set, map[string]Value{"tag": strs("dev", "qa")}, true, CondOK)
	})

	t.Run("nested expected lists are flattened and combined", func(t *testing.T) {
		set := ConditionSet{"IpAddress": {"src": {strs("10.1.2.0/24", "10.2.0.0/16")}}}
		clauseOK(t, set, map[string]Value{"src": strs("10.2.5.5")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"src": strs("172.16.0.1")}, false, CondNoMatch)
	})

	// boundary cases that must stay distinguishable
	t.Run("missing key vs empty group", func(t *testing.T) {
		set := setOf("StringEquals", "tag", StringV("prod"))
		clauseOK(t, set, map[string]Value{}, false, CondKeyMissing)
		clauseOK(t, set, map[string]Value{"tag": strs()}, false, CondEmptySet)
	})

	t.Run("IfExists with missing key and multivalue present key", func(t *testing.T) {
		miss := setOf("StringNotEqualsIfExists", "tag", StringV("prod"))
		clauseOK(t, miss, map[string]Value{}, true, CondOK)
		clauseOK(t, miss, map[string]Value{"tag": strs("dev", "qa")}, true, CondOK)
		clauseOK(t, miss, map[string]Value{"tag": strs("dev", "prod")}, false, CondNoMatch)
	})
}

func TestIPConditionClauses(t *testing.T) {
	cases := []struct {
		name       string
		op         string
		expected   string
		actual     string
		want       bool
		wantReason ConditionReason
	}{
		{"IpAddress hit", "IpAddress", "10.1.2.0/24", "10.1.2.7", true, CondOK},
		{"IpAddress boundary network addr", "IpAddress", "10.1.2.0/24", "10.1.2.0", true, CondOK},
		{"IpAddress boundary broadcast addr", "IpAddress", "10.1.2.0/24", "10.1.2.255", true, CondOK},
		{"IpAddress miss just outside", "IpAddress", "10.1.2.0/24", "10.1.3.0", false, CondNoMatch},
		{"IpAddress v6 hit", "IpAddress", "2001:db8::/32", "2001:db8::abcd", true, CondOK},
		{"IpAddress v6 miss", "IpAddress", "2001:db8::/32", "2001:db9::1", false, CondNoMatch},
		{"NotIpAddress outside", "NotIpAddress", "10.1.2.0/24", "192.0.2.1", true, CondOK},
		{"NotIpAddress inside fails", "NotIpAddress", "10.1.2.0/24", "10.1.2.9", false, CondNoMatch},
		{"NotIpAddress boundary network addr fails", "NotIpAddress", "10.1.2.0/24", "10.1.2.0", false, CondNoMatch},
		{"bad actual address", "IpAddress", "10.1.2.0/24", "not-an-ip", false, CondInvalidValue},
		{"bad expected netblock", "IpAddress", "10.1.2.0/99", "10.1.2.1", false, CondInvalidValue},
		{"NotIpAddress bad netblock still errors", "NotIpAddress", "nope", "10.1.2.1", false, CondInvalidValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set := setOf(c.op, "src", StringV(c.expected))
			ctx := map[string]Value{"src": StringV(c.actual)}
			clauseOK(t, set, ctx, c.want, c.wantReason)
		})
	}

	t.Run("NotIpAddress whole-group semantics", func(t *testing.T) {
		set := setOf("NotIpAddress", "srcs", StringV("10.1.2.0/24"))
		// one address in the excluded prefix -> clause fails regardless of the other
		clauseOK(t, set, map[string]Value{"srcs": strs("10.1.2.5", "192.0.2.1")}, false, CondNoMatch)
		clauseOK(t, set, map[string]Value{"srcs": strs("192.0.2.1", "198.51.100.7")}, true, CondOK)
	})

	t.Run("ForAllValues IpAddress", func(t *testing.T) {
		set := setOf("ForAllValues:IpAddress", "srcs", StringV("10.0.0.0/8"))
		clauseOK(t, set, map[string]Value{"srcs": strs("10.1.2.5", "10.9.9.9")}, true, CondOK)
		clauseOK(t, set, map[string]Value{"srcs": strs("10.1.2.5", "192.0.2.1")}, false, CondNoMatch)
	})
}

func TestARNConditionClauses(t *testing.T) {
	cases := []struct {
		name       string
		op         string
		pattern    string
		arn        string
		want       bool
		wantReason ConditionReason
	}{
		{"ArnLike exact", "ArnLike", "arn:aws:s3:::bucket/key", "arn:aws:s3:::bucket/key", true, CondOK},
		{"ArnLike wildcard hit", "ArnLike", "arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b", true, CondOK},
		{"ArnLike wildcard miss", "ArnLike", "arn:aws:s3:::bucket/*", "arn:aws:s3:::other/x", false, CondNoMatch},
		{"ArnEquals alias", "ArnEquals", "arn:aws:sqs:us-east-1:1:q", "arn:aws:sqs:us-east-1:1:q", true, CondOK},
		{"ArnNotLike outside", "ArnNotLike", "arn:aws:s3:::secret/*", "arn:aws:s3:::public/o", true, CondOK},
		{"ArnNotLike inside fails", "ArnNotLike", "arn:aws:s3:::secret/*", "arn:aws:s3:::secret/o", false, CondNoMatch},
		{"empty actual arn invalid", "ArnLike", "arn:aws:s3:::b/*", "", false, CondInvalidValue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set := setOf(c.op, "res", StringV(c.pattern))
			ctx := map[string]Value{"res": StringV(c.arn)}
			clauseOK(t, set, ctx, c.want, c.wantReason)
		})
	}

	t.Run("ArnNotLike whole-group semantics", func(t *testing.T) {
		set := setOf("ArnNotLike", "resources", StringV("arn:aws:s3:::secret/*"))
		clauseOK(t, set,
			map[string]Value{"resources": strs("arn:aws:s3:::public/o", "arn:aws:s3:::secret/o")},
			false, CondNoMatch)
		clauseOK(t, set,
			map[string]Value{"resources": strs("arn:aws:s3:::public/o", "arn:aws:sqs::1:q")},
			true, CondOK)
	})
}

func TestEmptyExpectedValueSet(t *testing.T) {
	set := ConditionSet{"StringEquals": {"k": {}}}
	clauseOK(t, set, map[string]Value{"k": StringV("v")}, false, CondEmptySet)
}
