package policies

import "testing"

// evalOne is a small helper: evaluate a single clause and report the outcome.
func evalOne(t *testing.T, op string, key string, expected []Value, ctx map[string]Value) (bool, ConditionReason) {
	t.Helper()
	outcomes, ok := EvaluateConditions(ConditionSet{Operator(op): ConditionMap{key: expected}}, ctx)
	if len(outcomes) != 1 {
		t.Fatalf("want exactly one outcome, got %+v", outcomes)
	}
	return ok, outcomes[0].Reason
}

func TestQuantifierDefaultsToAnyValue(t *testing.T) {
	ctx := map[string]Value{"tags": ListV(StringV("dev"), StringV("prod"))}

	// No explicit quantifier: at least one value matching is enough, and the
	// conclusion must not depend on the number or order of values.
	if ok, _ := evalOne(t, "StringEquals", "tags", []Value{StringV("prod")}, ctx); !ok {
		t.Fatal("default quantifier must accept when any value matches")
	}
	ctxReversed := map[string]Value{"tags": ListV(StringV("prod"), StringV("dev"))}
	if ok, _ := evalOne(t, "StringEquals", "tags", []Value{StringV("prod")}, ctxReversed); !ok {
		t.Fatal("default quantifier must be order-independent")
	}
	if ok, r := evalOne(t, "StringEquals", "tags", []Value{StringV("staging")}, ctx); ok || r != CondNoMatch {
		t.Fatalf("no value matches: got ok=%v reason=%s", ok, r)
	}

	// Single-value behavior must be identical to the historical semantics.
	single := map[string]Value{"tags": StringV("prod")}
	if ok, _ := evalOne(t, "StringEquals", "tags", []Value{StringV("prod")}, single); !ok {
		t.Fatal("single value equality regressed")
	}
	if ok, r := evalOne(t, "StringEquals", "tags", []Value{StringV("dev")}, single); ok || r != CondNoMatch {
		t.Fatalf("single value mismatch regressed: ok=%v reason=%s", ok, r)
	}
}

func TestForAllValuesQuantifier(t *testing.T){
	allProd := map[string]Value{"tags": ListV(StringV("prod"), StringV("prod"))}
	mixed := map[string]Value{"tags": ListV(StringV("dev"), StringV("prod"))}

	if ok, _ := evalOne(t, "ForAllValues:StringEquals", "tags", []Value{StringV("prod")}, allProd); !ok {
		t.Fatal("ForAllValues must accept when every value matches")
	}
	ok, reason := evalOne(t, "ForAllValues:StringEquals", "tags", []Value{StringV("prod")}, mixed)
	if ok || reason != CondNoMatch {
		t.Fatalf("ForAllValues must reject when one value misses: ok=%v reason=%s", ok, reason)
	}
	// Each value may match a different member of the expected set.
	if ok, _ := evalOne(t, "ForAllValues:StringEquals", "tags",
		[]Value{StringV("dev"), StringV("prod")}, mixed); !ok {
		t.Fatal("ForAllValues must accept when each value matches some expected member")
	}
	// Explicit ForAnyValue on the same mixed set still passes.
	if ok, _ := evalOne(t, "ForAnyValue:StringEquals", "tags", []Value{StringV("prod")}, mixed); !ok {
		t.Fatal("ForAnyValue must accept when at least one value matches")
	}
	// Quantifier composes with the IfExists suffix.
	if ok, _ := evalOne(t, "ForAllValues:StringEqualsIfExists", "absent", []Value{StringV("x")}, mixed); !ok {
		t.Fatal("ForAllValues:...IfExists must tolerate a missing key")
	}
}

func TestNegatedOperatorsUseWholeSetExclusion(t *testing.T) {
	// One actual value inside the exclusion set fails the clause even though
	// another actual value is outside it.
	ctx := map[string]Value{"tags": ListV(StringV("dev"), StringV("prod"))}
	ok, reason := evalOne(t, "StringNotEquals", "tags", []Value{StringV("prod")}, ctx)
	if ok || reason != CondNoMatch {
		t.Fatalf("one value in the exclusion set must fail the clause: ok=%v reason=%s", ok, reason)
	}
	// Same for the explicit quantifiers: negation always applies to the set.
	if ok, _ := evalOne(t, "ForAnyValue:StringNotEquals", "tags", []Value{StringV("prod")}, ctx); ok {
		t.Fatal("ForAnyValue:StringNotEquals must still fail when any value is excluded")
	}
	if ok, _ := evalOne(t, "ForAllValues:StringNotEquals", "tags", []Value{StringV("prod")}, ctx); ok {
		t.Fatal("ForAllValues:StringNotEquals must still fail when any value is excluded")
	}
	// No actual value in the exclusion set -> clause holds.
	if ok, _ := evalOne(t, "StringNotEquals", "tags", []Value{StringV("staging")}, ctx); !ok {
		t.Fatal("negated clause must hold when no value is excluded")
	}
	// Exclusion set with several members: any overlap fails.
	ok, _ = evalOne(t, "StringNotEquals", "tags", []Value{StringV("staging"), StringV("dev")}, ctx)
	if ok {
		t.Fatal("overlap with any exclusion member must fail the clause")
	}
	// Single-value negation keeps the historical conclusion.
	single := map[string]Value{"tags": StringV("prod")}
	if ok, _ := evalOne(t, "StringNotEquals", "tags", []Value{StringV("dev")}, single); !ok {
		t.Fatal("single-value negation regressed (different value must pass)")
	}
	if ok, _ := evalOne(t, "StringNotEquals", "tags", []Value{StringV("prod")}, single); ok {
		t.Fatal("single-value negation regressed (equal value must fail)")
	}
	// StringNotLike follows the same whole-set rule.
	likeCtx := map[string]Value{"arns": ListV(StringV("arn:aws:s3:::public/a"), StringV("arn:aws:s3:::secret/b"))}
	if ok, _ := evalOne(t, "StringNotLike", "arns", []Value{StringV("arn:aws:s3:::secret/*")}, likeCtx); ok {
		t.Fatal("StringNotLike must fail when any value matches the excluded pattern")
	}
}

func TestEmptyAndMissingBoundaries(t *testing.T) {
	empty := map[string]Value{"tags": ListV()}

	// Positive operator over an empty set: stable, distinguishable failure.
	ok, reason := evalOne(t, "StringEquals", "tags", []Value{StringV("prod")}, empty)
	if ok || reason != CondEmptyValueSet {
		t.Fatalf("empty set + positive op: ok=%v reason=%s", ok, reason)
	}
	ok, reason = evalOne(t, "ForAllValues:StringEquals", "tags", []Value{StringV("prod")}, empty)
	if ok || reason != CondEmptyValueSet {
		t.Fatalf("empty set + ForAllValues: ok=%v reason=%s", ok, reason)
	}
	// Negated operator over an empty set: vacuously satisfied.
	if ok, _ := evalOne(t, "StringNotEquals", "tags", []Value{StringV("prod")}, empty); !ok {
		t.Fatal("empty set must satisfy a negated clause (nothing is excluded)")
	}
	// Missing key is a different, distinguishable outcome.
	ok, reason = evalOne(t, "StringEquals", "tags", []Value{StringV("prod")}, map[string]Value{})
	if ok || reason != CondKeyMissing {
		t.Fatalf("missing key: ok=%v reason=%s", ok, reason)
	}
	if ok, _ := evalOne(t, "StringNotEquals", "tags", []Value{StringV("prod")}, map[string]Value{}); ok {
		t.Fatal("missing key must fail even a negated clause (fail-closed)")
	}
	if ok, _ := evalOne(t, "StringNotEqualsIfExists", "tags", []Value{StringV("prod")}, map[string]Value{}); !ok {
		t.Fatal("IfExists must tolerate a missing key even for negated operators")
	}
}
