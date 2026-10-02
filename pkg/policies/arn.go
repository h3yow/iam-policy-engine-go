package policies

// MatchARN reports whether arn matches the ARN pattern.
//
// Matching uses the same glob semantics as action/resource patterns
// ('*' any sequence, '?' exactly one character, everything else literal and
// case-sensitive). ARN comparison is whole-string: the pattern "*" matches any
// ARN, and "arn:aws:s3:::bucket/*" matches object ARNs of that bucket.
//
// Neither side may be empty; callers validate that beforehand and report it as
// an invalid-value condition error rather than silently treating it as a miss.
func MatchARN(pattern, arn string) bool {
	if pattern == "" || arn == "" {
		return false
	}
	return MatchPattern(pattern, arn)
}
