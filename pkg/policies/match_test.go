package policies

import "testing"

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:*", "ec2:RunInstances", false},
		{"s3:Get?", "s3:Get", false}, // '?' needs exactly one char
		{"s3:Get?", "s3:GetX", true},
		{"arn:*:bucket/*/object", "arn:aws:bucket/a/object", true},
		{"arn:*:bucket/*/object", "arn:aws:bucket/a/b/object", true}, // '*' spans '/'
		{"arn:*:bucket/*/object", "arn:aws:bucket/xobject", false},
		{"a*b*c", "axxbxxc", true},
		{"a*b*c", "axxbxx", false},
		{"exact", "exact", true},
		{"exact", "exactx", false},
		{"", "", true},
		{"", "x", false},
		{"prefix-*", "prefix-", true}, // '*' may match empty
		// Exclusion-style boundaries rely on '*' not crossing segments
		// incorrectly: e.g. bucket/* must not match "bucket" alone.
		{"bucket/*", "bucket/", true},
		{"bucket/*", "bucket", false},
	}
	for _, c := range cases {
		if got := MatchPattern(c.pattern, c.name); got != c.want {
			t.Errorf("MatchPattern(%q,%q)=%v want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	if MatchAny(nil, "anything") {
		t.Error("empty pattern list must not match")
	}
	if !MatchAny([]string{"ec2:*", "s3:Get*"}, "s3:GetObject") {
		t.Error("one matching pattern should make MatchAny true")
	}
	if MatchAny([]string{"ec2:*", "sqs:*"}, "s3:GetObject") {
		t.Error("no matching pattern should be false")
	}
}
