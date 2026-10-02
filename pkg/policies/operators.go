package policies

import (
	"fmt"
	"strings"
	"time"
)

// operatorSpec maps a base operator name (quantifier prefix and IfExists
// suffix already stripped) to:
//   - rel:     the element-vs-element comparison;
//   - kind:    the value kind the operator operates on;
//   - negated: whether the operator carries exclusion ("not") semantics;
//   - known:   whether the name is recognized at all.
func operatorSpec(op Operator) (rel relation, kind ValueKind, negated, known bool) {
	switch op {
	// ---- strings ----
	case "StringEquals", "StringEq":
		return strRel(func(g, e string) bool { return g == e }), KindString, false, true
	case "StringNotEquals", "StringNeq":
		// Negation is applied by the quantifier matrix; the relation stays the
		// positive base comparison (equality), so multivalue semantics become
		// "the whole actual group is disjoint from the expected set".
		return strRel(func(g, e string) bool { return g == e }), KindString, true, true
	case "StringEqualsIgnoreCase":
		return strRel(func(g, e string) bool { return strings.EqualFold(g, e) }), KindString, false, true
	case "StringLike":
		return strRel(func(g, e string) bool { return MatchPattern(e, g) }), KindString, false, true
	case "StringNotLike":
		return strRel(func(g, e string) bool { return MatchPattern(e, g) }), KindString, true, true

	// ---- numbers ----
	case "NumericEquals":
		return numRel(func(g, e float64) bool { return g == e }), KindNumber, false, true
	case "NumericNotEquals":
		return numRel(func(g, e float64) bool { return g == e }), KindNumber, true, true
	case "NumericLessThan":
		return numRel(func(g, e float64) bool { return g < e }), KindNumber, false, true
	case "NumericLessThanEquals":
		return numRel(func(g, e float64) bool { return g <= e }), KindNumber, false, true
	case "NumericGreaterThan":
		return numRel(func(g, e float64) bool { return g > e }), KindNumber, false, true
	case "NumericGreaterThanEquals":
		return numRel(func(g, e float64) bool { return g >= e }), KindNumber, false, true

	// ---- booleans ----
	case "Bool":
		return func(g, x Value) (pairStatus, string) {
			return boolMatch(g.Bool == x.Bool), ""
		}, KindBool, false, true

	// ---- dates ----
	case "DateEquals":
		return timeRel(func(a, b time.Time) bool { return a.Equal(b) }), KindTime, false, true
	case "DateBefore":
		return timeRel(func(a, b time.Time) bool { return a.Before(b) }), KindTime, false, true
	case "DateAfter":
		return timeRel(func(a, b time.Time) bool { return a.After(b) }), KindTime, false, true

	// ---- network location ----
	case "IpAddress":
		return ipRel(), KindString, false, true
	case "NotIpAddress":
		return ipRel(), KindString, true, true

	// ---- resource identity ----
	case "ArnLike", "ArnEquals":
		return arnRel(), KindString, false, true
	case "ArnNotLike", "ArnNotEquals":
		return arnRel(), KindString, true, true
	}
	return nil, KindMissing, false, false
}

// ---- small adapters that lift typed comparisons into relation ----

func strRel(f func(got, expected string) bool) relation {
	return func(g, e Value) (pairStatus, string) {
		return boolMatch(f(g.Str, e.Str)), ""
	}
}

func numRel(f func(got, expected float64) bool) relation {
	return func(g, e Value) (pairStatus, string) {
		return boolMatch(f(g.Num, e.Num)), ""
	}
}

// timeRel lifts a time.Time comparison into the relation interface.
func timeRel(f func(a, b time.Time) bool) relation {
	return func(g, e Value) (pairStatus, string) {
		return boolMatch(f(g.When, e.When)), ""
	}
}

// ipRel builds the IpAddress / NotIpAddress element relation. The relation
// itself stays "positive" (membership); negation is handled by the quantifier
// matrix so the whole-group disjoint-set semantics apply uniformly.
func ipRel() relation {
	return func(g, e Value) (pairStatus, string) {
		rng, err := parseNetblock(e.Str)
		if err != nil {
			return statusValueError,
				fmt.Sprintf("expected value %q is not a valid IP address or CIDR prefix: %v", e.Str, err)
		}
		ip, err := parseAddress(g.Str)
		if err != nil {
			return statusValueError,
				fmt.Sprintf("actual value %q is not a valid IP address", g.Str)
		}
		return boolMatch(rng.contains(ip)), ""
	}
}

func arnRel() relation {
	return func(g, e Value) (pairStatus, string) {
		if strings.TrimSpace(g.Str) == "" {
			return statusValueError, "actual ARN must not be empty"
		}
		if strings.TrimSpace(e.Str) == "" {
			return statusValueError, "expected ARN pattern must not be empty"
		}
		return boolMatch(MatchARN(e.Str, g.Str)), ""
	}
}

func boolMatch(b bool) pairStatus {
	if b {
		return statusMatch
	}
	return statusNoMatch
}
