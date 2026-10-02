package policies

import "testing"

func TestParseNewOperatorsAndQuantifiers(t *testing.T) {
	doc := []byte(`{"Statement":[{
	  "Sid":"net","Effect":"Allow","Action":"s3:GetObject","Resource":"*",
	  "Condition":{
	    "IpAddress":         {"src":["10.0.0.0/8","2001:db8::/32"]},
	    "NotIpAddress":      {"blocked":["192.0.2.0/24"]},
	    "ForAllValues:ArnLike": {"res":["arn:aws:s3:::bucket/*"]},
	    "ForAnyValue:StringNotEqualsIfExists": {"env":["prod"]}
	  }
	}]}`)
	p, err := ParsePolicy(SourceIdentity, doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conds := p.Statements[0].Conditions
	for _, op := range []Operator{"IpAddress", "NotIpAddress", "ForAllValues:ArnLike", "ForAnyValue:StringNotEqualsIfExists"} {
		if _, ok := conds[op]; !ok {
			t.Fatalf("operator %q missing from parsed conditions: %+v", op, conds)
		}
	}
	srcs := conds["IpAddress"]["src"]
	if len(srcs) != 2 || srcs[0].Str != "10.0.0.0/8" || srcs[1].Str != "2001:db8::/32" {
		t.Fatalf("ip values not parsed as strings: %+v", srcs)
	}

	// End-to-end semantics through the parser: all inside -> allow.
	ctx := map[string]Value{
		"src":     ListV(StringV("10.1.2.3"), StringV("10.9.9.9")),
		"blocked": StringV("198.51.100.1"),
		"res":     StringV("arn:aws:s3:::bucket/object"),
	}
	outs, ok := EvaluateConditions(conds, ctx)
	for _, o := range outs {
		t.Logf("PARSED CLAUSE op=%s key=%s success=%v reason=%s", o.Operator, o.Key, o.Success, o.Reason)
	}
	if !ok {
		t.Fatalf("want all clauses satisfied, got %+v", outs)
	}

	// One blocked address -> NotIpAddress whole-group failure.
	ctx2 := map[string]Value{
		"src":     StringV("10.0.0.1"),
		"blocked": ListV(StringV("198.51.100.1"), StringV("192.0.2.5")),
		"res":     StringV("arn:aws:s3:::bucket/object"),
	}
	if _, ok := EvaluateConditions(conds, ctx2); ok {
		t.Fatal("a single address inside the NotIpAddress exclusion set must fail the clause")
	}
}
