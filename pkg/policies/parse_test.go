package policies

import (
	"testing"
)

func TestParsePolicyBasic(t *testing.T) {
	doc := []byte(`{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Sid":"r","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
	  ]
	}`)
	p, err := ParsePolicy(SourceIdentity, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statements) != 1 {
		t.Fatalf("want 1 statement, got %d", len(p.Statements))
	}
	st := p.Statements[0]
	if st.Effect != Allow || st.Sid != "r" {
		t.Fatalf("unexpected statement: %+v", st)
	}
	if len(st.Actions) != 1 || st.Actions[0] != "s3:GetObject" {
		t.Fatalf("action should be normalized to list: %v", st.Actions)
	}
	if p.Source != SourceIdentity {
		t.Fatalf("source not preserved")
	}
}

func TestParsePolicySingleStatementObject(t *testing.T) {
	doc := []byte(`{"Statement": {"Effect":"Deny","Action":["ec2:*"],"Resource":["*"]}}`)
	p, err := ParsePolicy(SourceSession, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statements) != 1 || p.Statements[0].Effect != Deny {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseNotActionAndCondition(t *testing.T) {
	doc := []byte(`{
	  "Statement": [{
	    "Sid":"x","Effect":"Allow",
	    "NotAction":["iam:*"],
	    "NotResource":["arn:aws:s3:::secret/*"],
	    "Condition":{
	      "StringEquals":{"env":["prod"]},
	      "NumericGreaterThan":{"count":[10]},
	      "Bool":{"mfa":[true]}
	    }
	  }]
	}`)
	p, err := ParsePolicy(SourceBoundary, doc)
	if err != nil {
		t.Fatal(err)
	}
	st := p.Statements[0]
	if !st.UseNotAction || !st.UseNotResource {
		t.Fatalf("not-flags not set: %+v", st)
	}
	if got := st.Conditions["StringEquals"]["env"][0]; got.Kind != KindString || got.Str != "prod" {
		t.Fatalf("string cond wrong: %+v", got)
	}
	if got := st.Conditions["NumericGreaterThan"]["count"][0]; got.Kind != KindNumber || got.Num != 10 {
		t.Fatalf("number cond wrong: %+v", got)
	}
	if got := st.Conditions["Bool"]["mfa"][0]; got.Kind != KindBool || got.Bool != true {
		t.Fatalf("bool cond wrong: %+v", got)
	}
}

func TestParsePolicyErrors(t *testing.T) {
	bad := []struct{ name, doc string }{
		{"invalid json", `{`},
		{"bad effect", `{"Statement":[{"Effect":"Maybe","Action":"a","Resource":"r"}]}`},
		{"both action kinds", `{"Statement":[{"Effect":"Allow","Action":"a","NotAction":"b","Resource":"r"}]}`},
		{"no resource", `{"Statement":[{"Effect":"Allow","Action":"a"}]}`},
		{"empty array", `{"Statement":[{"Effect":"Allow","Action":[],"Resource":"r"}]}`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParsePolicy(SourceIdentity, []byte(c.doc)); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}
