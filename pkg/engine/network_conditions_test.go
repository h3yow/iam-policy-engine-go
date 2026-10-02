package engine

import (
	"testing"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

func TestNetworkAndARNConditionsEndToEnd(t *testing.T) {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
	  {"Sid":"vpn-objects","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::app/*",
	   "Condition":{
	     "ForAllValues:IpAddress":  {"aws:SourceIp":["10.0.0.0/8","2001:db8::/32"]},
	     "NotIpAddress":            {"aws:BlockedIp":["10.1.2.0/24"]},
	     "ArnLike":                 {"bucket":["arn:aws:s3:::app/*"]}
	   }},
	  {"Sid":"quarantine","Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::app/quar/*"}
	]}`)}
	e := New(id, nil, nil)

	req := func(ips, bucket string) Request {
		r := baseRequest("s3:GetObject", "arn:aws:s3:::app/data")
		vs := []policies.Value{}
		for _, ip := range splitCSV(ips) {
			vs = append(vs, policies.StringV(ip))
		}
		r.Context = map[string]policies.Value{
			"aws:SourceIp":  policies.ListV(vs...),
			"aws:BlockedIp": policies.ListV(vs...),
			"bucket":        policies.StringV(bucket),
		}
		return r
	}

	t.Run("all sources inside corp ranges and outside quarantine subnet", func(t *testing.T) {
		r := req("10.5.0.1,2001:db8::abcd", "arn:aws:s3:::app/data")
		res := e.Evaluate(r)
		logResult(t, r, res)
		if res.Reason != ReasonAllowed {
			t.Fatalf("want allow, got %s", res.Reason)
		}
	})

	t.Run("one source in excluded subnet denies despite the other being fine", func(t *testing.T) {
		r := req("10.5.0.1,10.1.2.77", "arn:aws:s3:::app/data")
		res := e.Evaluate(r)
		logResult(t, r, res)
		if res.Reason != ReasonConditionFailed || !hasCondReason(res, policies.CondNoMatch) {
			t.Fatalf("want condition_failed/did_not_match, got %s %+v", res.Reason, res.Conditions)
		}
	})

	t.Run("malformed source address is invalid_value, never silently unmatched", func(t *testing.T) {
		r := req("10.5.0.1,not-an-ip", "arn:aws:s3:::app/data")
		res := e.Evaluate(r)
		logResult(t, r, res)
		if res.Reason != ReasonConditionFailed || !hasCondReason(res, policies.CondInvalidValue) {
			t.Fatalf("want condition_failed/invalid_value, got %s %+v", res.Reason, res.Conditions)
		}
	})

	t.Run("ARN pattern not matched denies", func(t *testing.T) {
		r := req("10.5.0.1", "arn:aws:s3:::other/data")
		res := e.Evaluate(r)
		logResult(t, r, res)
		if res.Reason != ReasonConditionFailed {
			t.Fatalf("want condition_failed, got %s", res.Reason)
		}
	})

	t.Run("explicit deny still wins over matching network conditions", func(t *testing.T) {
		r := baseRequest("s3:GetObject", "arn:aws:s3:::app/quar/x")
		r.Context = map[string]policies.Value{
			"aws:SourceIp":  policies.StringV("10.5.0.1"),
			"aws:BlockedIp": policies.StringV("10.5.0.1"),
			"bucket":        policies.StringV("arn:aws:s3:::app/quar/x"),
		}
		res := e.Evaluate(r)
		logResult(t, r, res)
		if res.Reason != ReasonExplicitDeny {
			t.Fatalf("want explicit_deny, got %s", res.Reason)
		}
	})
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
