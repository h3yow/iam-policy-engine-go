package policy

import "strings"

// MatchResult is the outcome of matching an action/resource against a
// statement pattern set.
type MatchResult int

const (
	MatchNoMatch  MatchResult = iota
	MatchPositive             // matches an Action/Resource pattern
	MatchNegative             // applies because the value is NOT in NotAction/NotResource
)

// MatchAction reports whether and how an action matches the statement's
// Action / NotAction patterns.
//
// Action matching is case-insensitive (cloud actions such as "s3:GetObject"
// are case-insensitive), while glob '*' is supported in every pattern.
func MatchAction(action string, s Statement) MatchResult {
	a := strings.ToLower(action)
	if len(s.Actions) > 0 {
		for _, p := range s.Actions {
			if matchPattern(strings.ToLower(p), a) {
				return MatchPositive
			}
		}
		return MatchNoMatch
	}
	// NotAction: the statement applies to every action EXCEPT the listed
	// patterns. A request is matched-negatively only when none of the
	// exclusion patterns hit.
	for _, p := range s.NotActions {
		if matchPattern(strings.ToLower(p), a) {
			return MatchNoMatch // explicitly excluded action
		}
	}
	return MatchNegative
}

// MatchResource reports whether and how a resource matches the statement's
// Resource / NotResource patterns.
//
// Resource matching is case-sensitive with glob '*' support.
func MatchResource(resource string, s Statement) MatchResult {
	if len(s.Resources) > 0 {
		for _, p := range s.Resources {
			if matchPattern(p, resource) {
				return MatchPositive
			}
		}
		return MatchNoMatch
	}
	for _, p := range s.NotResources {
		if matchPattern(p, resource) {
			return MatchNoMatch // explicitly excluded resource
		}
	}
	return MatchNegative
}

// matchPattern reports whether value matches a single glob pattern.
// Only '*' is special: it matches any (possibly empty) sequence of bytes.
// A pattern without '*' requires an exact match; a trailing '*' is the
// common prefix form. Everything else, including '?', is literal.
func matchPattern(pattern, value string) bool {
	pi, vi := 0, 0
	starP, starV := -1, 0
	for vi < len(value) {
		if pi < len(pattern) && (pattern[pi] == value[vi]) {
			pi++
			vi++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starP = pi
			starV = vi
			pi++
		} else if starP >= 0 {
			pi = starP + 1
			starV++
			vi = starV
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
