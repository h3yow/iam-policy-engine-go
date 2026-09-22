package policies

// MatchPattern reports whether name matches the glob-like pattern.
//
// Semantics:
//   - '*' matches any sequence of characters, including the empty sequence;
//   - '?' matches exactly one character;
//   - every other character matches itself (case-sensitive);
//   - an empty pattern matches only the empty name.
//
// This is a backtracking implementation equivalent to translating the pattern
// into ".* / ." regex fragments, but kept allocation-light and deterministic.
func MatchPattern(pattern, name string) bool {
	var (
		p, n  int
		starP = -1 // index in pattern of the last '*'
		starN int  // index in name where the '*' match restart begins
	)
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == name[n] || pattern[p] == '?'):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			starP = p
			starN = n
			p++
		case starP != -1:
			// Backtrack: let the previous '*' absorb one more character.
			p = starP + 1
			starN++
			n = starN
		default:
			return false
		}
	}
	// Trailing '*'s may match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchAny reports whether name matches at least one of the patterns.
// An empty pattern list never matches.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if MatchPattern(p, name) {
			return true
		}
	}
	return false
}
