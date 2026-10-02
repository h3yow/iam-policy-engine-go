package policies

import "testing"

func setOf(op string, key string, vals ...Value) ConditionSet {
	return ConditionSet{Operator(op): ConditionMap{key: vals}}
}

func TestEvaluateConditions(t *testing.T) {
	ctx := map[string]Value{
		"env":   StringV("prod"),
		"count": NumberV(3),
		"flag":  BoolV(true),
		"envs":  ListV(StringV("dev"), StringV("prod")),
	}

	cases := []struct {
		name   string
		set    ConditionSet
		ctx    map[string]Value
		ok     bool
		reason ConditionReason
	}{
		{"empty set", nil, ctx, true, CondOK},
		{"string equals hit", setOf("StringEquals", "env", StringV("prod")), ctx, true, CondOK},
		{"string equals miss", setOf("StringEquals", "env", StringV("dev")), ctx, false, CondNoMatch},
		{"string like wildcard hit", setOf("StringLike", "env", StringV("pr*")), ctx, true, CondOK},
		{"string like wildcard must not over-match", setOf("StringLike", "env", StringV("dev*")), ctx, false, CondNoMatch},
		{"list value any-match", setOf("StringEquals", "envs", StringV("prod")), ctx, true, CondOK},
		{"negation hit", setOf("StringNotEquals", "env", StringV("dev")), ctx, true, CondOK},
		{"key missing denies", setOf("StringEquals", "nope", StringV("x")), ctx, false, CondKeyMissing},
		{"IfExists ignores missing key", setOf("StringEqualsIfExists", "nope", StringV("x")), ctx, true, CondOK},
		{"type mismatch", setOf("NumericEquals", "env", NumberV(1)), ctx, false, CondTypeMismatch},
		{"numeric mismatch", setOf("NumericGreaterThan", "count", NumberV(9)), ctx, false, CondNoMatch},
		{"unknown operator", setOf("QuantumEquals", "env", StringV("x")), ctx, false, CondUnknownOperator},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outcomes, ok := EvaluateConditions(c.set, c.ctx)
			if ok != c.ok {
				t.Fatalf("ok=%v want %v (outcomes=%+v)", ok, c.ok, outcomes)
			}
			if !ok {
				found := false
				for _, o := range outcomes {
					if o.Reason == c.reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("want an outcome with reason %q, got %+v", c.reason, outcomes)
				}
			}
		})
	}
}

func TestEvaluateConditionsOrderIndependent(t *testing.T) {
	// Two different map insertion orders must produce identical outcome slices.
	a := ConditionSet{}
	a["StringEquals"] = ConditionMap{"env": {StringV("prod")}}
	a["NumericGreaterThan"] = ConditionMap{"count": {NumberV(1)}}

	b := ConditionSet{}
	b["NumericGreaterThan"] = ConditionMap{"count": {NumberV(1)}}
	b["StringEquals"] = ConditionMap{"env": {StringV("prod")}}

	oa, _ := EvaluateConditions(a, map[string]Value{"env": StringV("prod"), "count": NumberV(3)})
	ob, _ := EvaluateConditions(b, map[string]Value{"count": NumberV(3), "env": StringV("prod")})
	if len(oa) != len(ob) {
		t.Fatalf("outcome length differs: %d vs %d", len(oa), len(ob))
	}
	for i := range oa {
		if oa[i] != ob[i] {
			t.Fatalf("outcome %d differs: %+v vs %+v", i, oa[i], ob[i])
		}
	}
}
