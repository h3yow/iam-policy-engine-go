package policies

import (
	"sort"
	"strings"
)

// ConditionOutcome describes how a single condition operator/key clause
// evaluated against the request context.
type ConditionOutcome struct {
	Operator Operator
	Key      string
	Success  bool
	Reason   ConditionReason
}

// ConditionReason distinguishes the different failure modes of a clause.
//
// Every non-ok reason causes the enclosing statement NOT to match: the engine
// is fail-closed, so missing keys, type mismatches and unknown operators can
// never produce an Allow by accident.
type ConditionReason string

const (
	CondOK              ConditionReason = "ok"
	CondKeyMissing      ConditionReason = "condition_key_missing"
	CondTypeMismatch    ConditionReason = "condition_type_mismatch"
	CondUnknownOperator ConditionReason = "condition_unknown_operator"
	CondNoMatch         ConditionReason = "condition_did_not_match"
	// CondEmptyValueSet: the context key held an empty list. Positive
	// operators cannot be satisfied by zero values; negated operators
	// succeed vacuously (nothing falls into the exclusion set).
	CondEmptyValueSet ConditionReason = "condition_empty_value_set"
	// CondInvalidValue: an actual or expected value was malformed for the
	// operator's domain (e.g. an unparseable IP/CIDR). Fail-closed and
	// distinguishable from an ordinary no-match.
	CondInvalidValue ConditionReason = "condition_invalid_value"
)

// ifExistsSuffix mirrors the AWS-style "...IfExists" qualifier: when present,
// a missing context key makes the clause succeed instead of failing.
const ifExistsSuffix = "IfExists"

// Quantifier selects how a multi-valued context key is reduced to a single
// boolean for positive (non-negated) operators.
type Quantifier int

const (
	// QuantAny is the default: at least one actual value must satisfy the
	// comparison. For single-valued keys this is exactly the historical
	// behavior, so existing policies are unaffected.
	QuantAny Quantifier = iota
	// QuantAll requires EVERY actual value to satisfy the comparison
	// against at least one expected value.
	QuantAll
)

// quantifier prefixes recognized in front of the operator name.
const (
	forAllValuesPrefix = "ForAllValues:"
	forAnyValuePrefix  = "ForAnyValue:"
)

// EvaluateConditions evaluates every clause of a statement against ctx.
//
// Clauses within an operator group and operator groups themselves are visited
// in sorted order so that the outcome list is independent of map iteration
// order (identical policies always yield identical explanations).
// It returns the ordered outcomes and whether all clauses succeeded.
func EvaluateConditions(set ConditionSet, ctx map[string]Value) ([]ConditionOutcome, bool) {
	if len(set) == 0 {
		return nil, true
	}
	ops := make([]string, 0, len(set))
	for op := range set {
		ops = append(ops, string(op))
	}
	sort.Strings(ops)

	var outcomes []ConditionOutcome
	allOK := true
	for _, opName := range ops {
		op := Operator(opName)
		group := set[op]
		keys := make([]string, 0, len(group))
		for k := range group {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			out := ConditionOutcome{Operator: op, Key: key}
			got, present := ctx[key]
			if !present {
				if strings.HasSuffix(opName, ifExistsSuffix) {
					out.Success, out.Reason = true, CondOK
				} else {
					out.Success, out.Reason = false, CondKeyMissing
					allOK = false
				}
				outcomes = append(outcomes, out)
				continue
			}
			ok, reason := evalClause(op, got, group[key])
			out.Success, out.Reason = ok, reason
			if !ok {
				allOK = false
			}
			outcomes = append(outcomes, out)
		}
	}
	return outcomes, allOK
}

// flatten unwraps list values on either side of a comparison.
func flatten(v Value) []Value {
	if v.Kind == KindList {
		return v.List
	}
	return []Value{v}
}

// evalClause evaluates one (operator, key, expected-values) triple.
//
// Multi-value semantics:
//   - The operator name may carry a "ForAllValues:" / "ForAnyValue:" prefix
//     (combinable with the "IfExists" suffix). Without a prefix the default
//     is ForAnyValue, which for single-valued keys reproduces the historical
//     behavior exactly; the result never depends on how many values the
//     context key holds or on their order.
//   - Negated operators (StringNotEquals, StringNotLike, NumericNotEquals,
//     NotIpAddress, ArnNotLike, ...) ALWAYS use whole-set exclusion
//     semantics regardless of the quantifier: the clause succeeds only when
//     NO actual value matches ANY expected value. One actual value falling
//     inside the exclusion set fails the clause, even if other actual
//     values are outside it.
//   - An empty actual value set fails positive operators with
//     CondEmptyValueSet and satisfies negated operators vacuously; both
//     outcomes are stable and distinguishable from a missing key
//     (CondKeyMissing) and from an ordinary mismatch (CondNoMatch).
//   - ALL expected values are validated against the operator's domain, even
//     when an earlier member already matches. A malformed member anywhere in
//     the list (e.g. "10.0.0.0/33" beside a matching "10.0.0.0/8") therefore
//     always yields CondInvalidValue, for both positive and negated
//     operators, regardless of the members' order or of which member the
//     actual value hits. The typo can never be hidden by another member that
//     matches.
func evalClause(op Operator, got Value, expected []Value) (bool, ConditionReason) {
	name := string(op)
	if strings.HasSuffix(name, ifExistsSuffix) {
		name = strings.TrimSuffix(name, ifExistsSuffix)
		// Missing-key tolerance was already handled by the caller.
	}

	quant := QuantAny
	if strings.HasPrefix(name, forAllValuesPrefix) {
		quant = QuantAll
		name = strings.TrimPrefix(name, forAllValuesPrefix)
	} else if strings.HasPrefix(name, forAnyValuePrefix) {
		quant = QuantAny
		name = strings.TrimPrefix(name, forAnyValuePrefix)
	}

	pred, kind, known := operatorSpec(Operator(name))
	if !known {
		return false, CondUnknownOperator
	}
	negated := isNegatedOperator(Operator(name))

	gotElems := flatten(got)
	var expElems []Value
	for _, e := range expected {
		expElems = append(expElems, flatten(e)...)
	}
	if len(expElems) == 0 {
		return false, CondNoMatch
	}

	// Empty actual set: stable, distinguishable boundary outcome.
	if len(gotElems) == 0 {
		if negated {
			return true, CondOK // nothing can fall into the exclusion set
		}
		return false, CondEmptyValueSet
	}

	// matches[i] reports whether actual value i satisfies the predicate
	// against at least one expected value of the right kind.
	//
	// EVERY (actual, expected) pair is examined: validation must never stop
	// after the first matching expected value. Otherwise a malformed member
	// later in the expected list (e.g. "10.0.0.0/33" sitting behind a matching
	// "10.0.0.0/8") would be skipped entirely, so the clause conclusion — and
	// even whether the typo is reported — would depend on the order of the
	// expected values. Scanning all pairs makes match/no-match, type errors
	// and invalid-value failures independent of list order on either side.
	matches := make([]bool, len(gotElems))
	typeError := false
	invalid := false
	for i, g := range gotElems {
		if g.Kind != kind {
			typeError = true
			continue
		}
		for _, x := range expElems {
			if x.Kind != kind {
				typeError = true
				continue
			}
			ok, valid := pred(g, x)
			if !valid {
				invalid = true
				continue
			}
			// No break on match: the remaining expected values are still
			// examined so a malformed member anywhere in the list is detected.
			matches[i] = matches[i] || ok
		}
	}

	// Malformed values (e.g. bad CIDR) are reported before anything else:
	// they must never be silently treated as a match or a non-match.
	if invalid {
		return false, CondInvalidValue
	}

	if negated {
		for _, m := range matches {
			if m {
				return false, CondNoMatch // one value fell into the exclusion set
			}
		}
		if typeError {
			return false, CondTypeMismatch
		}
		return true, CondOK
	}

	switch quant {
	case QuantAll:
		all := true
		for _, m := range matches {
			if !m {
				all = false
				break
			}
		}
		if all {
			return true, CondOK
		}
	default: // QuantAny
		for _, m := range matches {
			if m {
				return true, CondOK
			}
		}
	}
	if typeError {
		return false, CondTypeMismatch
	}
	return false, CondNoMatch
}

// isNegatedOperator reports whether the operator carries exclusion ("not")
// semantics and therefore always compares the whole actual value set against
// the exclusion set.
func isNegatedOperator(op Operator) bool {
	switch op {
	case "StringNotEquals", "StringNeq", "StringNotLike",
		"NumericNotEquals", "NotIpAddress", "ArnNotLike":
		return true
	}
	return false
}

// predicate compares one actual value against one expected value. It reports
// whether the comparison matched and whether both operands were well-formed
// for the operator's domain (valid == false surfaces as CondInvalidValue).
type predicate func(got, expected Value) (matched, valid bool)

// alwaysValid adapts a simple boolean comparison into a predicate.
func alwaysValid(f func(g, e Value) bool) predicate {
	return func(g, e Value) (bool, bool) { return f(g, e), true }
}

// operatorSpec maps an operator to its comparison predicate and the value kind
// it operates on.
func operatorSpec(op Operator) (predicate, ValueKind, bool) {
	switch op {
	// ---- strings ----
	case "StringEquals", "StringEq":
		return alwaysValid(func(g, e Value) bool { return g.Str == e.Str }), KindString, true
	case "StringNotEquals", "StringNeq":
		return alwaysValid(func(g, e Value) bool { return g.Str == e.Str }), KindString, true
	case "StringEqualsIgnoreCase":
		return alwaysValid(func(g, e Value) bool { return strings.EqualFold(g.Str, e.Str) }), KindString, true
	case "StringLike":
		return alwaysValid(func(g, e Value) bool { return MatchPattern(e.Str, g.Str) }), KindString, true
	case "StringNotLike":
		return alwaysValid(func(g, e Value) bool { return MatchPattern(e.Str, g.Str) }), KindString, true

	// ---- numbers ----
	case "NumericEquals":
		return alwaysValid(func(g, e Value) bool { return g.Num == e.Num }), KindNumber, true
	case "NumericNotEquals":
		return alwaysValid(func(g, e Value) bool { return g.Num == e.Num }), KindNumber, true
	case "NumericLessThan":
		return alwaysValid(func(g, e Value) bool { return g.Num < e.Num }), KindNumber, true
	case "NumericLessThanEquals":
		return alwaysValid(func(g, e Value) bool { return g.Num <= e.Num }), KindNumber, true
	case "NumericGreaterThan":
		return alwaysValid(func(g, e Value) bool { return g.Num > e.Num }), KindNumber, true
	case "NumericGreaterThanEquals":
		return alwaysValid(func(g, e Value) bool { return g.Num >= e.Num }), KindNumber, true

	// ---- booleans ----
	case "Bool":
		return alwaysValid(func(g, e Value) bool { return g.Bool == e.Bool }), KindBool, true

	// ---- dates ----
	case "DateEquals":
		return alwaysValid(func(g, e Value) bool { return g.When.Equal(e.When) }), KindTime, true
	case "DateBefore":
		return alwaysValid(func(g, e Value) bool { return g.When.Before(e.When) }), KindTime, true
	case "DateAfter":
		return alwaysValid(func(g, e Value) bool { return g.When.After(e.When) }), KindTime, true

	// ---- network location ----
	case "IpAddress", "NotIpAddress":
		return ipInExpected, KindString, true

	// ---- resource identifiers ----
	case "ArnLike", "ArnNotLike":
		return alwaysValid(func(g, e Value) bool { return MatchPattern(e.Str, g.Str) }), KindString, true
	}
	return nil, KindMissing, false
}
