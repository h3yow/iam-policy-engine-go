package engine

import (
	"testing"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

var fixedNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func mustPolicy(t testing.TB, src policies.Source, doc string) policies.Policy {
	t.Helper()
	p, err := policies.ParsePolicy(src, []byte(doc))
	if err != nil {
		t.Fatalf("parse policy: %v\n%s", err, doc)
	}
	return p
}

func credsValid() *policies.Credentials {
	return &policies.Credentials{AccessKeyID: "AKIA-TEST", ExpiresAt: fixedNow.Add(time.Hour)}
}

// logResult prints request context, matched rules and the final conclusion,
// as required for explainability in unit-test output.
func logResult(t *testing.T, req Request, res Result) {
	t.Helper()
	t.Logf("REQUEST principal=%q action=%q resource=%q creds=%v context=%v",
		req.Principal, req.Action, req.Resource, req.Creds != nil, req.Context)
	if len(res.Hits) == 0 {
		t.Logf("HIT RULES: (none)")
	}
	for _, h := range res.Hits {
		t.Logf("HIT RULE: source=%s sid=%s effect=%s actions=%v resources=%v notAction=%v notResource=%v",
			h.Source, h.Sid, h.Effect, h.Actions, h.Resources, h.NotAction, h.NotResource)
	}
	for _, c := range res.Conditions {
		t.Logf("CONDITION: op=%s key=%s success=%v reason=%s", c.Operator, c.Key, c.Success, c.Reason)
	}
	t.Logf("DECISION: %s reason=%s detail=%q", res.Decision, res.Reason, res.Detail)
}

func baseRequest(action, resource string) Request {
	return Request{Principal: "user-1", Action: action, Resource: resource,
		Context: map[string]policies.Value{}, Creds: credsValid(), Now: fixedNow}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"all","Effect":"Allow","Action":"*","Resource":"*"},
		{"Sid":"deny-delete","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}
	]}`)}
	e := New(id, nil, nil)

	allowed := e.Evaluate(baseRequest("s3:GetObject", "arn:aws:s3:::b/o"))
	logResult(t, baseRequest("s3:GetObject", "arn:aws:s3:::b/o"), allowed)
	if allowed.Decision != DecisionAllow || allowed.Reason != ReasonAllowed {
		t.Fatalf("GetObject should be allowed, got %s/%s", allowed.Decision, allowed.Reason)
	}

	denied := e.Evaluate(baseRequest("s3:DeleteBucket", "arn:aws:s3:::b"))
	logResult(t, baseRequest("s3:DeleteBucket", "arn:aws:s3:::b"), denied)
	if denied.Decision != DecisionDeny || denied.Reason != ReasonExplicitDeny {
		t.Fatalf("DeleteBucket must be explicitly denied even with Allow *, got %s/%s", denied.Decision, denied.Reason)
	}
	// The deny hit must be reported.
	found := false
	for _, h := range denied.Hits {
		if h.Sid == "deny-delete" && h.Effect == policies.Deny {
			found = true
		}
	}
	if !found {
		t.Fatalf("explicit deny statement missing from hits: %+v", denied.Hits)
	}
}

func TestDefaultDenyWhenNoMatch(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"only-s3","Effect":"Allow","Action":"s3:*","Resource":"*"}
	]}`)}
	e := New(id, nil, nil)

	req := baseRequest("ec2:RunInstances", "arn:aws:ec2:us-east-1:1:instance/i-1")
	res := e.Evaluate(req)
	logResult(t, req, res)
	if res.Decision != DecisionDeny || res.Reason != ReasonDefaultDeny {
		t.Fatalf("unmatched action must default-deny, got %s/%s", res.Decision, res.Reason)
	}
}

func TestWildcardAndExclusionBoundaries(t *testing.T) {
	// Allow everything except iam:* (NotAction) and the secret bucket
	// (NotResource).
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"wide","Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::secret/*"}
	]}`)}
	e := New(id, nil, nil)

	cases := []struct {
		name             string
		action, resource string
		want             Decision
		reason           ReasonCode
	}{
		{"regular s3 get allowed", "s3:GetObject", "arn:aws:s3:::app/o", DecisionAllow, ReasonAllowed},
		{"excluded iam action denied", "iam:CreateUser", "arn:aws:iam::1:user/x", DecisionDeny, ReasonDefaultDeny},
		{"excluded secret resource denied", "s3:GetObject", "arn:aws:s3:::secret/key", DecisionDeny, ReasonDefaultDeny},
		// wildcard must not leak across the excluded pattern by accident
		{"iam wildcard prefix not matched by other service", "iamx:Get", "arn:aws:iamx::1:x", DecisionAllow, ReasonAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := baseRequest(c.action, c.resource)
			res := e.Evaluate(req)
			logResult(t, req, res)
			if res.Decision != c.want || res.Reason != c.reason {
				t.Fatalf("got %s/%s want %s/%s", res.Decision, res.Reason, c.want, c.reason)
			}
		})
	}
}

func TestConditionFailureReasons(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"c","Effect":"Allow","Action":"s3:GetObject","Resource":"*",
		 "Condition":{"StringEquals":{"env":"prod"}, "NumericGreaterThan":{"count":10}}}
	]}`)}
	e := New(id, nil, nil)

	// 1) condition matches -> allow
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"env": policies.StringV("prod"), "count": policies.NumberV(20)}
	res := e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonAllowed {
		t.Fatalf("want allow, got %s", res.Reason)
	}

	// 2) key present but wrong type -> distinguishable mismatch reason
	req = baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"env": policies.StringV("prod"), "count": policies.StringV("20")}
	res = e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonConditionFailed {
		t.Fatalf("type mismatch must surface as condition_failed, got %s", res.Reason)
	}
	if !hasCondReason(res, policies.CondTypeMismatch) {
		t.Fatalf("want condition_type_mismatch outcome, got %+v", res.Conditions)
	}

	// 3) key missing -> distinguishable missing reason, request denied
	req = baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"env": policies.StringV("prod")}
	res = e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonConditionFailed {
		t.Fatalf("missing key must surface as condition_failed, got %s", res.Reason)
	}
	if !hasCondReason(res, policies.CondKeyMissing) {
		t.Fatalf("want condition_key_missing outcome, got %+v", res.Conditions)
	}
}

func TestUnknownOperatorIsFailClosed(t *testing.T) {
	// Hand-built statement with an unknown operator (parser cannot express it
	// from JSON unless raw; construct via domain types).
	id := []policies.Policy{{Source: policies.SourceIdentity, Statements: []policies.Statement{{
		Sid:       "weird",
		Effect:    policies.Allow,
		Actions:   []string{"s3:GetObject"},
		Resources: []string{"*"},
		Conditions: policies.ConditionSet{
			"QuantumEquals": policies.ConditionMap{"x": {policies.StringV("y")}},
		},
	}}}}
	e := New(id, nil, nil)
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"x": policies.StringV("y")}
	res := e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonConditionFailed || !hasCondReason(res, policies.CondUnknownOperator) {
		t.Fatalf("unknown operator must fail closed as condition_failed, got %s %+v", res.Reason, res.Conditions)
	}
}

func TestPermissionBoundaryTightens(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"all","Effect":"Allow","Action":"*","Resource":"*"}
	]}`)}
	boundary := []policies.Policy{mustPolicy(t, policies.SourceBoundary, `{"Statement":[
		{"Sid":"only-read","Effect":"Allow","Action":"s3:Get*","Resource":"*"}
	]}`)}
	e := New(id, boundary, nil)

	ok := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	res := e.Evaluate(ok)
	logResult(t, ok, res)
	if res.Reason != ReasonAllowed {
		t.Fatalf("boundary permits reads, got %s", res.Reason)
	}

	blocked := baseRequest("s3:PutObject", "arn:aws:s3:::b/o")
	res = e.Evaluate(blocked)
	logResult(t, blocked, res)
	if res.Reason != ReasonBoundaryDeny {
		t.Fatalf("boundary must tighten away writes, got %s", res.Reason)
	}

	// A boundary can never widen: removing identity allow yields default deny
	// even though the boundary would allow.
	e2 := New(nil, boundary, nil)
	res = e2.Evaluate(ok)
	logResult(t, ok, res)
	if res.Reason != ReasonDefaultDeny {
		t.Fatalf("boundary alone must not grant, got %s", res.Reason)
	}
}

func TestSessionPolicyTightens(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"all","Effect":"Allow","Action":"*","Resource":"*"}
	]}`)}
	sess := []policies.Policy{mustPolicy(t, policies.SourceSession, `{"Statement":[
		{"Sid":"deny-secret","Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}
	]}`)}
	e := New(id, nil, sess)

	req := baseRequest("s3:GetObject", "arn:aws:s3:::secret/k")
	res := e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonExplicitDeny {
		t.Fatalf("session explicit deny must win, got %s", res.Reason)
	}

	req2 := baseRequest("s3:GetObject", "arn:aws:s3:::public/k")
	res = e.Evaluate(req2)
	logResult(t, req2, res)
	if res.Reason != ReasonSessionDeny {
		t.Fatalf("session without allow for this resource must deny (intersection), got %s", res.Reason)
	}
}

func TestCredentialValidity(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"all","Effect":"Allow","Action":"*","Resource":"*"}
	]}`)}
	e := New(id, nil, nil)

	// missing credentials
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Creds = nil
	res := e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonCredentialsMissing {
		t.Fatalf("got %s", res.Reason)
	}

	// expired credentials
	req = baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Creds = &policies.Credentials{ExpiresAt: fixedNow.Add(-time.Minute)}
	res = e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonCredentialsExpired {
		t.Fatalf("got %s", res.Reason)
	}

	// not yet valid (future-dated)
	req = baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Creds = &policies.Credentials{IssuedAt: fixedNow.Add(time.Hour)}
	res = e.Evaluate(req)
	logResult(t, req, res)
	if res.Reason != ReasonCredentialsNotReady {
		t.Fatalf("got %s", res.Reason)
	}
}

func TestOrderAndDuplicateDeterminism(t *testing.T) {
	deny := `{"Statement":[{"Sid":"d","Effect":"Deny","Action":"s3:Delete*","Resource":"*"}]}`
	allow := `{"Statement":[{"Sid":"a","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

	mk := func() *Engine {
		return New([]policies.Policy{
			mustPolicy(t, policies.SourceIdentity, allow),
			mustPolicy(t, policies.SourceIdentity, deny),
			mustPolicy(t, policies.SourceIdentity, deny), // duplicate
		}, nil, nil)
	}
	mkReversed := func() *Engine {
		return New([]policies.Policy{
			mustPolicy(t, policies.SourceIdentity, deny),
			mustPolicy(t, policies.SourceIdentity, allow),
		}, nil, nil)
	}

	req := baseRequest("s3:DeleteObject", "arn:aws:s3:::b/o")
	r1 := mk().Evaluate(req)
	r2 := mkReversed().Evaluate(req)
	logResult(t, req, r1)

	if r1.Decision != DecisionDeny || r1.Reason != ReasonExplicitDeny {
		t.Fatalf("got %s/%s", r1.Decision, r1.Reason)
	}
	if r1.Reason != r2.Reason || r1.Decision != r2.Decision || len(r1.Hits) != len(r2.Hits) {
		t.Fatalf("order changed the result:\n%+v\n%+v", r1, r2)
	}
	// duplicate deny statement must be collapsed to one hit
	denyHits := 0
	for _, h := range r1.Hits {
		if h.Sid == "d" {
			denyHits++
		}
	}
	if denyHits != 1 {
		t.Fatalf("duplicate statements not de-duplicated: %d deny hits", denyHits)
	}
}

func hasCondReason(res Result, r policies.ConditionReason) bool {
	for _, c := range res.Conditions {
		if c.Reason == r {
			return true
		}
	}
	return false
}
