package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ConditionResult is the tri-state result of evaluating a condition block.
type ConditionResult int

const (
	CondError ConditionResult = iota // type mismatch, unknown operator, missing key ...
	CondFalse
	CondTrue
)

// ConditionError explains why a condition could not be evaluated normally.
type ConditionError struct {
	Reason ConditionErrorReason
	Key    string
	Detail string
}

// ConditionErrorReason is the distinguishable cause of a condition error.
type ConditionErrorReason string

const (
	CondErrUnknownOperator ConditionErrorReason = "UnknownOperator"
	CondErrMissingKey      ConditionErrorReason = "MissingKey"
	CondErrTypeMismatch    ConditionErrorReason = "TypeMismatch"
	CondErrInvalidValue    ConditionErrorReason = "InvalidValue"
)

func (e *ConditionError) Error() string {
	return fmt.Sprintf("condition error on key %q: %s (%s)", e.Key, e.Reason, e.Detail)
}

// EvalCondition evaluates one condition block against the request context.
//
// Deterministic error rules (all evaluated fail-closed by the engine):
//   - UnknownOperator: the operator name is not supported.
//   - MissingKey:      the condition key does not exist in the context
//     (the Null operator is the sole exception).
//   - TypeMismatch:    the key value's declared type does not fit the
//     operator family (e.g. NumericEquals on a String).
//   - InvalidValue:    a comparison value cannot be parsed (bad number,
//     CIDR, bool or epoch value).
//
// For a single-valued key the condition is true when the key value satisfies
// the operator against ANY of the condition values. For a multi-valued key
// EVERY key value must satisfy it against some condition value.
func EvalCondition(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	switch {
	case isStringOp(c.Operator):
		return evalString(c, ctx)
	case isNumericOp(c.Operator):
		return evalNumeric(c, ctx)
	case c.Operator == "Bool":
		return evalBool(c, ctx)
	case isDateOp(c.Operator):
		return evalDate(c, ctx)
	case c.Operator == "IpAddress" || c.Operator == "NotIpAddress":
		return evalIP(c, ctx)
	case c.Operator == "Null":
		return evalNull(c, ctx)
	default:
		return CondError, &ConditionError{Reason: CondErrUnknownOperator, Key: c.Key,
			Detail: fmt.Sprintf("operator %q is not supported", c.Operator)}
	}
}

// ---- string operators ------------------------------------------------------

func isStringOp(op Operator) bool {
	switch op {
	case "StringEquals", "StringNotEquals",
		"StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
		"StringLike", "StringNotLike":
		return true
	}
	return false
}

func evalString(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	elems, cerr := keyStringElems(c, ctx)
	if cerr != nil {
		return CondError, cerr
	}
	ignoreCase := strings.Contains(string(c.Operator), "IgnoreCase")
	glob := strings.Contains(string(c.Operator), "Like")
	negated := strings.Contains(string(c.Operator), "Not")

	norm := func(s string) string { return s }
	if ignoreCase {
		norm = strings.ToLower
	}
	pred := func(keyVal, condVal string) bool {
		k, v := norm(keyVal), norm(condVal)
		if glob {
			return matchPattern(v, k)
		}
		return k == v
	}
	return aggregate(elems, c.Values, negated, pred), nil
}

// ---- numeric operators -----------------------------------------------------

func isNumericOp(op Operator) bool {
	switch op {
	case "NumericEquals", "NumericNotEquals", "NumericLessThan",
		"NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		return true
	}
	return false
}

func evalNumeric(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	v, ok := lookupKey(c, ctx)
	if !ok {
		return CondError, missingKey(c)
	}
	if v.Type != TypeNumber {
		return CondError, typeMismatch(c, "number", v.Type)
	}
	nums := make([]float64, 0, len(c.Values))
	for _, raw := range c.Values {
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return CondError, invalidValue(c, fmt.Sprintf("not a number: %q", raw))
		}
		nums = append(nums, n)
	}
	pred := func(cond float64) bool {
		switch c.Operator {
		case "NumericEquals":
			return v.Num == cond
		case "NumericNotEquals":
			return v.Num != cond
		case "NumericLessThan":
			return v.Num < cond
		case "NumericLessThanEquals":
			return v.Num <= cond
		case "NumericGreaterThan":
			return v.Num > cond
		case "NumericGreaterThanEquals":
			return v.Num >= cond
		}
		return false
	}
	matchedAny := false
	for _, n := range nums {
		if pred(n) {
			matchedAny = true
			break
		}
	}
	return boolResult(matchedAny), nil
}

// ---- bool ------------------------------------------------------------------

func evalBool(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	v, ok := lookupKey(c, ctx)
	if !ok {
		return CondError, missingKey(c)
	}
	if v.Type != TypeBool {
		return CondError, typeMismatch(c, "Bool", v.Type)
	}
	for _, raw := range c.Values {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return CondError, invalidValue(c, fmt.Sprintf("not a bool: %q", raw))
		}
		if b == v.Bool {
			return CondTrue, nil
		}
	}
	return CondFalse, nil
}

// ---- date ------------------------------------------------------------------

func isDateOp(op Operator) bool {
	switch op {
	case "DateGreaterThan", "DateLessThan",
		"DateGreaterThanEquals", "DateLessThanEquals":
		return true
	}
	return false
}

func evalDate(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	v, ok := lookupKey(c, ctx)
	if !ok {
		return CondError, missingKey(c)
	}
	if v.Type != TypeDate {
		return CondError, typeMismatch(c, "Date", v.Type)
	}
	for _, raw := range c.Values {
		epoch, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return CondError, invalidValue(c, fmt.Sprintf("not an epoch timestamp: %q", raw))
		}
		var hit bool
		switch c.Operator {
		case "DateGreaterThan":
			hit = v.Num > epoch
		case "DateLessThan":
			hit = v.Num < epoch
		case "DateGreaterThanEquals":
			hit = v.Num >= epoch
		case "DateLessThanEquals":
			hit = v.Num <= epoch
		}
		if hit {
			return CondTrue, nil
		}
	}
	return CondFalse, nil
}

// ---- IP --------------------------------------------------------------------

func evalIP(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	elems, cerr := keyStringElems(c, ctx)
	if cerr != nil {
		return CondError, cerr
	}
	nets := make([]*net.IPNet, 0, len(c.Values))
	for _, raw := range c.Values {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return CondError, invalidValue(c, fmt.Sprintf("not a CIDR: %q", raw))
		}
		nets = append(nets, n)
	}
	contains := func(ipStr string) bool {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	// IpAddress: every key IP must be in some CIDR.
	// NotIpAddress: every key IP must be in NO CIDR.
	for _, ipStr := range elems {
		in := contains(ipStr)
		if c.Operator == "IpAddress" && !in {
			return CondFalse, nil
		}
		if c.Operator == "NotIpAddress" && in {
			return CondFalse, nil
		}
	}
	return CondTrue, nil
}

// ---- Null (existence) ------------------------------------------------------

func evalNull(c Condition, ctx *RequestContext) (ConditionResult, *ConditionError) {
	if len(c.Values) != 1 {
		return CondError, invalidValue(c, "Null requires exactly one value")
	}
	wantMissing, err := strconv.ParseBool(c.Values[0])
	if err != nil {
		return CondError, invalidValue(c, fmt.Sprintf("not a bool: %q", c.Values[0]))
	}
	_, present := ctx.Keys[c.Key]
	return boolResult(present != wantMissing), nil
}

// ---- helpers ---------------------------------------------------------------

func lookupKey(c Condition, ctx *RequestContext) (Value, bool) {
	if ctx.Keys == nil {
		return Value{}, false
	}
	v, ok := ctx.Keys[c.Key]
	return v, ok
}

// keyStringElems extracts the comparable string elements of a key value and
// enforces that the declared type is String.
func keyStringElems(c Condition, ctx *RequestContext) ([]string, *ConditionError) {
	v, ok := lookupKey(c, ctx)
	if !ok {
		return nil, missingKey(c)
	}
	if v.Type != TypeString {
		return nil, typeMismatch(c, "String", v.Type)
	}
	if len(v.Strs) > 0 {
		return v.Strs, nil
	}
	return []string{v.Str}, nil
}

// aggregate applies an equality/glob predicate with IAM-style quantifiers:
// every key element must match at least one condition value for a positive
// operator; for a negated operator no key element may match any value.
func aggregate(keyElems, condValues []string, negated bool, pred func(k, c string) bool) ConditionResult {
	for _, kv := range keyElems {
		matchedOne := false
		for _, cv := range condValues {
			if pred(kv, cv) {
				matchedOne = true
				break
			}
		}
		if !negated && !matchedOne {
			return CondFalse
		}
		if negated && matchedOne {
			return CondFalse
		}
	}
	return CondTrue
}

func boolResult(b bool) ConditionResult {
	if b {
		return CondTrue
	}
	return CondFalse
}

func missingKey(c Condition) *ConditionError {
	return &ConditionError{Reason: CondErrMissingKey, Key: c.Key,
		Detail: "condition key is not present in the request context"}
}

func typeMismatch(c Condition, want string, got ValueType) *ConditionError {
	return &ConditionError{Reason: CondErrTypeMismatch, Key: c.Key,
		Detail: fmt.Sprintf("operator %s requires %s, key has %s", c.Operator, want, got)}
}

func invalidValue(c Condition, detail string) *ConditionError {
	return &ConditionError{Reason: CondErrInvalidValue, Key: c.Key, Detail: detail}
}
