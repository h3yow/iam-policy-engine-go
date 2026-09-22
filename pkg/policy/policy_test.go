package policy

import (
	"testing"
)

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:*", "ec2:StartInstances", false},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other-bucket/x", false},
		{"exact:value", "exact:value", true},
		{"exact:value", "exact:valu", false},
		{"a*b*c", "axxbxxc", true},
		{"a*b*c", "axxbxx", false},
	}
	for _, tc := range cases {
		if got := matchPattern(tc.pattern, tc.value); got != tc.want {
			t.Errorf("matchPattern(%q,%q)=%v want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestMatchActionNotAction(t *testing.T) {
	pos := Statement{Actions: []string{"s3:Get*"}}
	if MatchAction("S3:getobject", pos) != MatchPositive {
		t.Error("actions should be case-insensitive")
	}
	if MatchAction("s3:PutObject", pos) != MatchNoMatch {
		t.Error("s3:PutObject must not match s3:Get*")
	}

	neg := Statement{NotActions: []string{"s3:Delete*"}}
	if MatchAction("s3:GetObject", neg) != MatchNegative {
		t.Error("non-excluded action must match negatively")
	}
	if MatchAction("s3:DeleteBucket", neg) != MatchNoMatch {
		t.Error("excluded action must not match NotAction")
	}
}

func TestMatchResourceNotResource(t *testing.T) {
	pos := Statement{Resources: []string{"arn:aws:s3:::shared/*"}}
	if MatchResource("arn:aws:s3:::shared/a", pos) != MatchPositive {
		t.Error("expected positive resource match")
	}
	if MatchResource("arn:aws:s3:::private/a", pos) != MatchNoMatch {
		t.Error("outside-prefix resource must not match")
	}
	neg := Statement{NotResources: []string{"arn:aws:s3:::secret/*"}}
	if MatchResource("arn:aws:s3:::secret/x", neg) != MatchNoMatch {
		t.Error("excluded resource must not match NotResource")
	}
	if MatchResource("arn:aws:s3:::open/x", neg) != MatchNegative {
		t.Error("non-excluded resource must match negatively")
	}
}

func TestParse(t *testing.T) {
	raw := []byte(`{
		"Version": "2012-10-17",
		"Id": "p1",
		"Statement": [
			{"Sid":"r","Effect":"Deny","Action":"s3:*","Resource":"*"},
			{"Effect":"Allow","Action":["ec2:Start*","ec2:Stop*"],"Resource":"*",
			 "Condition":{"StringEquals":{"aws:username":["alice","bob"]}}}
		]
	}`)
	d, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(d.Statements) != 2 {
		t.Fatalf("want 2 statements, got %d", len(d.Statements))
	}
	if got := d.Statements[1].Actions; len(got) != 2 || got[0] != "ec2:Start*" {
		t.Errorf("unexpected actions: %v", got)
	}
	if len(d.Statements[1].Conditions) != 1 || d.Statements[1].Conditions[0].Key != "aws:username" {
		t.Errorf("condition not parsed: %+v", d.Statements[1].Conditions)
	}
}

func TestParseInvalid(t *testing.T) {
	bad := []string{
		`{"Statement":[]}`,
		`{"Statement":[{"Effect":"Maybe","Action":"s3:*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"s3:*","NotAction":"x","Resource":"*"}]}`,
	}
	for i, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestParseConditionOrderCanonical(t *testing.T) {
	a := []byte(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*",
		"Condition":{"StringEquals":{"b":"1","a":"2"}}}]}`)
	b := []byte(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*",
		"Condition":{"StringEquals":{"a":"2","b":"1"}}}]}`)
	da, _ := Parse(a)
	db, _ := Parse(b)
	if da.Statements[0].Conditions[0].Key != db.Statements[0].Conditions[0].Key {
		t.Error("condition key order must be canonicalized (sorted)")
	}
}
