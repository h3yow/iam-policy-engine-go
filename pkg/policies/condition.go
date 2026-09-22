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
)

// ifExistsSuffix mirrors the AWS-style "...IfExists" qualifier: when present,
// a missing context key makes the clause succeed instead of failing.
const ifExistsSuffix = "IfExists"

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
func evalClause(op Operator, got Value, expected []Value) (bool, ConditionReason) {
	name := string(op)
	allowMissing := false
	if strings.HasSuffix(name, ifExistsSuffix) {
		name = strings.TrimSuffix(name, ifExistsSuffix)
		allowMissing = true
	}
	_ = allowMissing // presence was already handled by the caller

	pred, kind, known := operatorSpec(Operator(name))
	if !known {
		return false, CondUnknownOperator
	}

	gotElems := flatten(got)
	var expElems []Value
	for _, e := range expected {
		expElems = append(expElems, flatten(e)...)
	}
	if len(expElems) == 0 {
		return false, CondNoMatch
	}

	typeError := false
	for _, g := range gotElems {
		if g.Kind != kind {
			typeError = true
			continue
		}
		for _, x := range expElems {
			if x.Kind != kind {
				typeError = true
				continue
			}
			if pred(g, x) {
				return true, CondOK
			}
		}
	}
	if typeError {
		return false, CondTypeMismatch
	}
	return false, CondNoMatch
}

// predicate compares one actual value against one expected value.
type predicate func(got, expected Value) bool

// operatorSpec maps an operator to its comparison predicate and the value kind
// it operates on.
func operatorSpec(op Operator) (predicate, ValueKind, bool) {
	switch op {
	// ---- strings ----
	case "StringEquals", "StringEq":
		return func(g, e Value) bool { return g.Str == e.Str }, KindString, true
	case "StringNotEquals", "StringNeq":
		return func(g, e Value) bool { return g.Str != e.Str }, KindString, true
	case "StringEqualsIgnoreCase":
		return func(g, e Value) bool { return strings.EqualFold(g.Str, e.Str) }, KindString, true
	case "StringLike":
		return func(g, e Value) bool { return MatchPattern(e.Str, g.Str) }, KindString, true
	case "StringNotLike":
		return func(g, e Value) bool { return !MatchPattern(e.Str, g.Str) }, KindString, true

	// ---- numbers ----
	case "NumericEquals":
		return func(g, e Value) bool { return g.Num == e.Num }, KindNumber, true
	case "NumericNotEquals":
		return func(g, e Value) bool { return g.Num != e.Num }, KindNumber, true
	case "NumericLessThan":
		return func(g, e Value) bool { return g.Num < e.Num }, KindNumber, true
	case "NumericLessThanEquals":
		return func(g, e Value) bool { return g.Num <= e.Num }, KindNumber, true
	case "NumericGreaterThan":
		return func(g, e Value) bool { return g.Num > e.Num }, KindNumber, true
	case "NumericGreaterThanEquals":
		return func(g, e Value) bool { return g.Num >= e.Num }, KindNumber, true

	// ---- booleans ----
	case "Bool":
		return func(g, e Value) bool { return g.Bool == e.Bool }, KindBool, true

	// ---- dates ----
	case "DateEquals":
		return func(g, e Value) bool { return g.When.Equal(e.When) }, KindTime, true
	case "DateBefore":
		return func(g, e Value) bool { return g.When.Before(e.When) }, KindTime, true
	case "DateAfter":
		return func(g, e Value) bool { return g.When.After(e.When) }, KindTime, true
	}
	return nil, KindMissing, false
}
