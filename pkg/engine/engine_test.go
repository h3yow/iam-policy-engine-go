package engine

import (
	"testing"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/policy"
)

func mustParse(t *testing.T, src policy.SourceType, id, raw string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", id, err)
	}
	d.ID = id
	d.Source = policy.Source{Type: src, Name: id}
	return d
}

func s(action, resource string) *policy.RequestContext {
	return &policy.RequestContext{
		PrincipalARN: "arn:aws:iam::111111:user/alice",
		AccountID:    "111111",
		Action:       action,
		Resource:     resource,
		Now:          time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
	}
}

const allowAllS3 = `{"Version":"2012-10-17","Statement":[
	{"Sid":"AllowS3","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

func logEval(t *testing.T, ctx *policy.RequestContext, ev *Evaluation) {
	t.Helper()
	t.Logf("\n%s", Explain(ctx, ev))
}

func assertDeny(t *testing.T, ev *Evaluation, reason DenyReason) {
	t.Helper()
	if ev.Decision != DecisionDeny {
		t.Fatalf("want Deny, got %s", ev.Decision)
	}
	if ev.DenyReason != reason {
		t.Fatalf("want deny reason %s, got %s (%s)", reason, ev.DenyReason, ev.Detail)
	}
}

func TestExplicitDenyBeatsAllow(t *testing.T) {
	deny := mustParse(t, policy.SourceIdentity, "deny", `{"Statement":[
		{"Sid":"DenySecret","Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}]}`)
	allow := mustParse(t, policy.SourceIdentity, "allow", allowAllS3)
	eng := New([]*policy.Document{allow, deny}, nil, nil)

	ctx := s("s3:GetObject", "arn:aws:s3:::secret/passwords")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonExplicitDeny)

	// Reverse order: explicit deny must still win.
	eng2 := New([]*policy.Document{deny, allow}, nil, nil)
	ev2 := eng2.Evaluate(ctx, nil)
	assertDeny(t, ev2, ReasonExplicitDeny)
}

func TestDefaultDenyWhenNoMatch(t *testing.T) {
	allow := mustParse(t, policy.SourceIdentity, "allow", `{"Statement":[
		{"Effect":"Allow","Action":"ec2:StartInstances","Resource":"*"}]}`)
	eng := New([]*policy.Document{allow}, nil, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::bucket/a")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonNoMatch)
}

func TestAllowWhenMatched(t *testing.T) {
	allow := mustParse(t, policy.SourceIdentity, "allow", allowAllS3)
	eng := New([]*policy.Document{allow}, nil, nil)
	ctx := s("s3:PutObject", "arn:aws:s3:::bucket/a")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	if ev.Decision != DecisionAllow {
		t.Fatalf("want Allow, got %s (%s)", ev.Decision, ev.Detail)
	}
}

func TestNotActionNotResourceExclusion(t *testing.T) {
	// Everything except deletes, on everything except the secret bucket.
	doc := mustParse(t, policy.SourceIdentity, "p", `{"Statement":[
		{"Effect":"Allow","NotAction":"s3:Delete*","NotResource":"arn:aws:s3:::secret/*"}]}`)
	eng := New([]*policy.Document{doc}, nil, nil)

	ok := s("s3:GetObject", "arn:aws:s3:::shared/a")
	if ev := eng.Evaluate(ok, nil); ev.Decision != DecisionAllow {
		t.Fatalf("excluded-pair request should allow, got %s", ev.DenyReason)
	} else {
		logEval(t, ok, ev)
	}

	excludedAction := s("s3:DeleteBucket", "arn:aws:s3:::shared/a")
	ev := eng.Evaluate(excludedAction, nil)
	logEval(t, excludedAction, ev)
	assertDeny(t, ev, ReasonNoMatch)

	excludedResource := s("s3:GetObject", "arn:aws:s3:::secret/a")
	ev = eng.Evaluate(excludedResource, nil)
	logEval(t, excludedResource, ev)
	assertDeny(t, ev, ReasonNoMatch)
}

func TestConditionTypeMismatch(t *testing.T) {
	doc := mustParse(t, policy.SourceIdentity, "p", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*",
		 "Condition":{"NumericGreaterThan":{"session:age":"18"}}}]}`)
	eng := New([]*policy.Document{doc}, nil, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::b/a")
	ctx.Keys = map[string]policy.Value{"session:age": {Type: policy.TypeString, Str: "not-a-number"}}
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonConditionError)
	if ev.ConditionFail == nil || ev.ConditionFail.Reason != policy.CondErrTypeMismatch {
		t.Fatalf("want TypeMismatch, got %+v", ev.ConditionFail)
	}
}

func TestConditionMissingKey(t *testing.T) {
	doc := mustParse(t, policy.SourceIdentity, "p", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*",
		 "Condition":{"StringEquals":{"aws:username":"alice"}}}]}`)
	eng := New([]*policy.Document{doc}, nil, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::b/a")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonConditionError)
	if ev.ConditionFail == nil || ev.ConditionFail.Reason != policy.CondErrMissingKey {
		t.Fatalf("want MissingKey, got %+v", ev.ConditionFail)
	}
}

func TestConditionUnknownOperator(t *testing.T) {
	doc := mustParse(t, policy.SourceIdentity, "p", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*",
		 "Condition":{"MagicEquals":{"x":"y"}}}]}`)
	eng := New([]*policy.Document{doc}, nil, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::b/a")
	ctx.Keys = map[string]policy.Value{"x": {Type: policy.TypeString, Str: "y"}}
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonConditionError)
	if ev.ConditionFail.Reason != policy.CondErrUnknownOperator {
		t.Fatalf("want UnknownOperator, got %v", ev.ConditionFail.Reason)
	}
}

func TestConditionAllowThenFalse(t *testing.T) {
	doc := mustParse(t, policy.SourceIdentity, "p", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*",
		 "Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}]}`)
	eng := New([]*policy.Document{doc}, nil, nil)

	in := s("s3:GetObject", "arn:aws:s3:::b/a")
	in.Keys = map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeString, Str: "10.1.2.3"}}
	if ev := eng.Evaluate(in, nil); ev.Decision != DecisionAllow {
		t.Fatalf("in-CIDR should allow: %s", ev.Detail)
	}

	out := s("s3:GetObject", "arn:aws:s3:::b/a")
	out.Keys = map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeString, Str: "203.0.113.9"}}
	ev := eng.Evaluate(out, nil)
	logEval(t, out, ev)
	assertDeny(t, ev, ReasonNoMatch)
}

func TestPermissionBoundaryTightens(t *testing.T) {
	identity := mustParse(t, policy.SourceIdentity, "id", allowAllS3)
	boundary := mustParse(t, policy.SourceBoundary, "bd", `{"Statement":[
		{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::shared/*"}]}`)
	eng := New([]*policy.Document{identity}, []*policy.Document{boundary}, nil)

	inside := s("s3:GetObject", "arn:aws:s3:::shared/a")
	if ev := eng.Evaluate(inside, nil); ev.Decision != DecisionAllow {
		t.Fatalf("within boundary should allow: %s", ev.Detail)
	}

	outAction := s("s3:PutObject", "arn:aws:s3:::shared/a")
	ev := eng.Evaluate(outAction, nil)
	logEval(t, outAction, ev)
	assertDeny(t, ev, ReasonBoundaryNoMatch)

	outResource := s("s3:GetObject", "arn:aws:s3:::secret/a")
	ev = eng.Evaluate(outResource, nil)
	logEval(t, outResource, ev)
	assertDeny(t, ev, ReasonBoundaryNoMatch)
}

func TestPermissionBoundaryExplicitDeny(t *testing.T) {
	identity := mustParse(t, policy.SourceIdentity, "id", allowAllS3)
	boundary := mustParse(t, policy.SourceBoundary, "bd", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}]}`)
	eng := New([]*policy.Document{identity}, []*policy.Document{boundary}, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::secret/a")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonBoundaryDeny)
}

func TestSessionPolicyTightens(t *testing.T) {
	identity := mustParse(t, policy.SourceIdentity, "id", allowAllS3)
	session := mustParse(t, policy.SourceSession, "sess", `{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::shared/*"}]}`)
	eng := New([]*policy.Document{identity}, nil, []*policy.Document{session})

	inside := s("s3:GetObject", "arn:aws:s3:::shared/a")
	if ev := eng.Evaluate(inside, nil); ev.Decision != DecisionAllow {
		t.Fatalf("within session scope should allow: %s", ev.Detail)
	}
	outside := s("s3:DeleteObject", "arn:aws:s3:::shared/a")
	ev := eng.Evaluate(outside, nil)
	logEval(t, outside, ev)
	assertDeny(t, ev, ReasonSessionNoMatch)
}

func TestSessionPolicyCannotWiden(t *testing.T) {
	// Identity allows nothing; session says Allow s3:* — must NOT widen.
	identity := mustParse(t, policy.SourceIdentity, "id", `{"Statement":[
		{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`)
	session := mustParse(t, policy.SourceSession, "sess", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	eng := New([]*policy.Document{identity}, nil, []*policy.Document{session})
	ctx := s("s3:GetObject", "arn:aws:s3:::b/a")
	ev := eng.Evaluate(ctx, nil)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonNoMatch)
}

func TestCredentialsExpired(t *testing.T) {
	identity := mustParse(t, policy.SourceIdentity, "id", allowAllS3)
	eng := New([]*policy.Document{identity}, nil, nil)
	ctx := s("s3:GetObject", "arn:aws:s3:::b/a")

	expired := &Credentials{AccessKeyID: "AKIAEXPIRED", ExpiresAt: ctx.Now.Add(-time.Minute)}
	ev := eng.Evaluate(ctx, expired)
	logEval(t, ctx, ev)
	assertDeny(t, ev, ReasonCredentialsExpired)

	fresh := &Credentials{AccessKeyID: "AKIAFRESH", ExpiresAt: ctx.Now.Add(time.Hour)}
	if ev := eng.Evaluate(ctx, fresh); ev.Decision != DecisionAllow {
		t.Fatalf("fresh credentials should allow, got %s", ev.DenyReason)
	}
}

func TestContextMissing(t *testing.T) {
	identity := mustParse(t, policy.SourceIdentity, "id", allowAllS3)
	eng := New([]*policy.Document{identity}, nil, nil)

	for _, ctx := range []*policy.RequestContext{
		nil,
		{Action: "", Resource: "arn:x"},
		{Action: "s3:GetObject", Resource: ""},
	} {
		ev := eng.Evaluate(ctx, nil)
		if ev.DenyReason != ReasonContextMissing {
			t.Fatalf("want ContextMissing for %+v, got %s", ctx, ev.DenyReason)
		}
	}
}

func TestDeterministicAcrossOrderAndDuplicates(t *testing.T) {
	d1 := mustParse(t, policy.SourceIdentity, "p1", `{"Statement":[
		{"Effect":"Allow","Action":"s3:Get*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}]}`)
	d2 := mustParse(t, policy.SourceIdentity, "p2", `{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::shared/*"}]}`)
	ctx := s("s3:GetObject", "arn:aws:s3:::secret/x")

	run := func(docs ...*policy.Document) *Evaluation {
		return New(docs, nil, nil).Evaluate(ctx, nil)
	}
	a := run(d2, d1)
	b := run(d1, d2, d1, d2) // different order + duplicates
	logEval(t, ctx, a)
	if a.Decision != b.Decision || a.DenyReason != b.DenyReason {
		t.Fatalf("non-deterministic: %s/%s vs %s/%s", a.Decision, a.DenyReason, b.Decision, b.DenyReason)
	}
	if len(a.MatchedRules) != len(b.MatchedRules) {
		t.Fatalf("matched rule count differs across duplicate inputs: %d vs %d",
			len(a.MatchedRules), len(b.MatchedRules))
	}
}
