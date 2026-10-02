package policies

import (
	"fmt"
	"sort"
	"strings"
)

// ConditionOutcome describes how a single condition operator/key clause
// evaluated against the request context.
type ConditionOutcome struct {
	Operator Operator        `json:"operator"`
	Key      string          `json:"key"`
	Success  bool            `json:"success"`
	Reason   ConditionReason `json:"reason"`
	// Detail gives a human-readable, stable explanation for non-ok reasons
	// (e.g. which literal was malformed). It is empty for successful clauses.
	Detail string `json:"detail,omitempty"`
}

// ConditionReason distinguishes the different failure modes of a clause.
//
// Every non-ok reason causes the enclosing statement NOT to match: the engine
// is fail-closed, so missing keys, empty value groups, type mismatches,
// malformed literals and unknown operators can never produce an Allow.
type ConditionReason string

const (
	CondOK ConditionReason = "ok"
	// CondKeyMissing: the request context does not carry the key (and the
	// operator has no IfExists qualifier).
	CondKeyMissing ConditionReason = "condition_key_missing"
	// CondTypeMismatch: at least one actual or expected value has a type the
	// operator cannot compare.
	CondTypeMismatch ConditionReason = "condition_type_mismatch"
	// CondUnknownOperator: the operator name is not recognized.
	CondUnknownOperator ConditionReason = "condition_unknown_operator"
	// CondNoMatch: keys and types are fine, but no comparison succeeds under
	// the clause's quantifier semantics.
	CondNoMatch ConditionReason = "condition_did_not_match"
	// CondEmptySet: the key resolves to an empty value group, or the policy
	// clause lists no expected values. Kept separate from key_missing so the
	// two boundary cases can be told apart.
	CondEmptySet ConditionReason = "condition_empty_value_set"
	// CondInvalidValue: a literal is well-typed but structurally invalid for
	// the operator (bad IP address / netblock / ARN).
	CondInvalidValue ConditionReason = "condition_invalid_value"
)

// ifExistsSuffix mirrors the AWS-style "...IfExists" qualifier: when present,
// a missing context key makes the clause succeed instead of failing.
const ifExistsSuffix = "IfExists"

// Quantifier selects how a clause combines a group of actual context values
// with the group of expected policy values.
type Quantifier string

const (
	// QuantDefault is used for operators without an explicit quantifier
	// prefix. Its behavior is fixed and does NOT depend on value count:
	//   - positive operators ("equals", "like", IpAddress, ArnLike, ...):
	//     satisfied iff SOME actual value matches SOME expected value;
	//   - negated operators ("not equals", "not like", NotIpAddress, ...):
	//     the whole actual group must be disjoint from the exclusion set,
	//     i.e. EVERY actual value matches NO expected value. One actual value
	//     falling inside the excluded set fails the clause; other values
	//     being outside can never rescue it.
	QuantDefault Quantifier = ""
	// QuantForAll is the explicit "ForAllValues:" prefix: every actual value
	// must satisfy the expected group (for negated operators this is the same
	// disjoint-set rule as the default).
	QuantForAll Quantifier = "ForAllValues:"
	// QuantForAny is the explicit "ForAnyValue:" prefix: at least one actual
	// value must satisfy the comparison (for negated operators, at least one
	// actual value must escape the exclusion set).
	QuantForAny Quantifier = "ForAnyValue:"
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
					out.Detail = fmt.Sprintf("request context has no value for key %q", key)
					allOK = false
				}
				outcomes = append(outcomes, out)
				continue
			}
			ok, reason, detail := evalClause(op, got, group[key])
			out.Success, out.Reason, out.Detail = ok, reason, detail
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

// pairStatus is the outcome of comparing one actual element against one
// expected element.
type pairStatus int

const (
	statusMatch pairStatus = iota
	statusNoMatch
	statusTypeError
	statusValueError
)

// relation compares one actual value against one expected value, returning a
// status and, for structural errors, a stable detail message.
type relation func(got, expected Value) (pairStatus, string)

// evalClause evaluates one (operator, key, expected-values) triple.
func evalClause(op Operator, got Value, expected []Value) (bool, ConditionReason, string) {
	name := string(op)
	ifExists := false
	if strings.HasSuffix(name, ifExistsSuffix) {
		name = strings.TrimSuffix(name, ifExistsSuffix)
		ifExists = true
	}
	_ = ifExists // presence was already handled by EvaluateConditions

	quant := QuantDefault
	for _, q := range []Quantifier{QuantForAll, QuantForAny} {
		if strings.HasPrefix(name, string(q)) {
			quant = q
			name = strings.TrimPrefix(name, string(q))
			break
		}
	}

	rel, kind, negated, known := operatorSpec(Operator(name))
	if !known {
		return false, CondUnknownOperator, fmt.Sprintf("unknown condition operator %q", op)
	}

	gotElems := flatten(got)
	var expElems []Value
	for _, e := range expected {
		expElems = append(expElems, flatten(e)...)
	}
	if len(gotElems) == 0 {
		return false, CondEmptySet,
			fmt.Sprintf("key resolves to an empty value group for operator %q", name)
	}
	if len(expElems) == 0 {
		return false, CondEmptySet,
			fmt.Sprintf("operator %q lists no expected values", name)
	}

	// Evaluate the G x E comparison matrix in a fixed order. Structural errors
	// are collected across ALL pairs (never short-circuited), so a malformed
	// literal is reported even if another pair would have matched.
	rowMatched := make([]bool, len(gotElems))
	typeErr := ""
	valueErr := ""
	for gi, g := range gotElems {
		if g.Kind != kind && typeErr == "" {
			typeErr = fmt.Sprintf("operator %q requires %s values; actual value has type %s",
				name, kindName(kind), kindName(g.Kind))
		}
		for ei, x := range expElems {
			if x.Kind != kind && typeErr == "" {
				typeErr = fmt.Sprintf("operator %q requires %s values; expected value has type %s",
					name, kindName(kind), kindName(x.Kind))
			}
			if g.Kind != kind || x.Kind != kind {
				continue
			}
			st, detail := rel(g, x)
			switch st {
			case statusMatch:
				rowMatched[gi] = true
			case statusTypeError:
				if typeErr == "" {
					typeErr = detail
				}
			case statusValueError:
				if valueErr == "" {
					if detail == "" {
						detail = fmt.Sprintf("invalid value at actual[%d]/expected[%d] for operator %q", gi, ei, name)
					}
					valueErr = detail
				}
			}
		}
	}
	if valueErr != "" {
		return false, CondInvalidValue, valueErr
	}
	if typeErr != "" {
		return false, CondTypeMismatch, typeErr
	}

	satisfied := quantify(quant, negated, rowMatched)
	if !satisfied {
		return false, CondNoMatch, noMatchDetail(name, quant, negated, len(gotElems), len(expElems))
	}
	return true, CondOK, ""
}

// quantify implements the set-quantifier truth table over per-actual-row match
// flags. Let m(g) mean "some expected value matches actual value g":
//
//	                   positive operator   negated operator
//	default            exists g: m(g)       forall g: !m(g)  (disjoint sets)
//	ForAllValues:      forall g: m(g)       forall g: !m(g)  (disjoint sets)
//	ForAnyValue:       exists g: m(g)       exists g: !m(g)
//
// The default column is therefore independent of how many values the key
// carries, and a single actual value inside a negated exclusion set always
// fails regardless of the other values.
func quantify(quant Quantifier, negated bool, rowMatched []bool) bool {
	matched := 0
	for _, m := range rowMatched {
		if m {
			matched++
		}
	}
	switch {
	case negated && quant == QuantForAny:
		return matched < len(rowMatched) // some row escaped the exclusion set
	case negated:
		return matched == 0 // default / ForAll: fully disjoint
	case quant == QuantForAll:
		return matched == len(rowMatched) // every actual row covered
	default:
		return matched > 0 // default / ForAny: at least one row
	}
}

func noMatchDetail(name string, quant Quantifier, negated bool, gotN, expN int) string {
	switch {
	case negated && quant == QuantForAny:
		return fmt.Sprintf("operator %q: none of the %d actual values escapes the %d-value exclusion set", name, gotN, expN)
	case negated:
		return fmt.Sprintf("operator %q: at least one of the %d actual values falls inside the %d-value exclusion set", name, gotN, expN)
	case quant == QuantForAll:
		return fmt.Sprintf("operator %q: not all %d actual values match an expected value", name, gotN)
	default:
		return fmt.Sprintf("operator %q: none of the %d actual values matches any of the %d expected values", name, gotN, expN)
	}
}

func kindName(k ValueKind) string {
	switch k {
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindBool:
		return "bool"
	case KindTime:
		return "time"
	case KindList:
		return "list"
	default:
		return "missing"
	}
}
