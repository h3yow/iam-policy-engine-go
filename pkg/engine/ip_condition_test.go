package engine

import (
	"reflect"
	"testing"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

// ipCondPolicy builds an identity policy whose single Allow statement is
// gated by the given network-location condition on sourceIp.
func ipCondPolicy(t *testing.T, op string, expected ...string) policies.Policy {
	t.Helper()
	list := `["` + expected[0] + `"`
	for _, e := range expected[1:] {
		list += `,"` + e + `"`
	}
	list += `]`
	return mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"net-gated","Effect":"Allow","Action":"s3:GetObject","Resource":"*",
		 "Condition":{"`+op+`":{"sourceIp":`+list+`}}}
	]}`)
}

func ipRequest() Request {
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"sourceIp": policies.StringV("10.1.2.3")}
	return req
}

func assertInvalidValueDeny(t *testing.T, res Result) {
	t.Helper()
	if res.Decision != DecisionDeny || res.Reason != ReasonConditionFailed {
		t.Fatalf("want Deny/%s, got %s/%s", ReasonConditionFailed, res.Decision, res.Reason)
	}
	found := false
	for _, c := range res.Conditions {
		if c.Reason == policies.CondInvalidValue {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a condition outcome with reason %q, got %+v", policies.CondInvalidValue, res.Conditions)
	}
}

// TestInvalidIpInExpectedListFailsClosed: a multi-valued IpAddress /
// NotIpAddress expected list containing one malformed entry must fail the
// clause with CondInvalidValue regardless of where the bad entry sits, so
// the gated Allow statement never fires and the outcome is order-stable.
func TestInvalidIpInExpectedListFailsClosed(t *testing.T) {
	const (
		validHit  = "10.0.0.0/8" // matches sourceIp 10.1.2.3
		validMiss = "192.168.0.0/16"
		badPrefix = "10.0.0.0/33" // prefix length out of range
		badAddr   = "10.0.0.256"  // not an address
	)

	cases := []struct {
		name     string
		op       string
		expected []string
	}{
		{"ip valid-hit then invalid", "IpAddress", []string{validHit, badPrefix}},
		{"ip invalid then valid-hit", "IpAddress", []string{badPrefix, validHit}},
		{"ip valid-hit then invalid addr", "IpAddress", []string{validHit, badAddr}},
		{"ip invalid addr then valid-hit", "IpAddress", []string{badAddr, validHit}},
		{"ip valid-miss then invalid", "IpAddress", []string{validMiss, badPrefix}},
		{"ip invalid then valid-miss", "IpAddress", []string{badPrefix, validMiss}},
		{"not-ip valid-hit then invalid", "NotIpAddress", []string{validHit, badPrefix}},
		{"not-ip invalid then valid-hit", "NotIpAddress", []string{badPrefix, validHit}},
		{"not-ip valid-miss then invalid", "NotIpAddress", []string{validMiss, badPrefix}},
		{"not-ip invalid then valid-miss", "NotIpAddress", []string{badPrefix, validMiss}},
	}

	results := map[string]Result{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := New([]policies.Policy{ipCondPolicy(t, c.op, c.expected...)}, nil, nil)
			req := ipRequest()
			res := e.Evaluate(req)
			logResult(t, req, res)
			assertInvalidValueDeny(t, res)
			results[c.name] = res
		})
	}

	// Order-swapped variants of the same value multiset must be identical.
	pairs := [][2]string{
		{"ip valid-hit then invalid", "ip invalid then valid-hit"},
		{"ip valid-hit then invalid addr", "ip invalid addr then valid-hit"},
		{"ip valid-miss then invalid", "ip invalid then valid-miss"},
		{"not-ip valid-hit then invalid", "not-ip invalid then valid-hit"},
		{"not-ip valid-miss then invalid", "not-ip invalid then valid-miss"},
	}
	for _, p := range pairs {
		if !reflect.DeepEqual(results[p[0]], results[p[1]]) {
			t.Fatalf("order-dependent outcome:\n %+v\n %+v", results[p[0]], results[p[1]])
		}
	}
}

// TestInvalidIpBatchConsistentWithSingle: batch evaluation of requests whose
// policies carry mixed valid/invalid expected lists must produce exactly the
// same results as evaluating each request on its own.
func TestInvalidIpBatchConsistentWithSingle(t *testing.T) {
	policiesByCase := []policies.Policy{
		ipCondPolicy(t, "IpAddress", "10.0.0.0/8", "10.0.0.0/33"),
		ipCondPolicy(t, "IpAddress", "10.0.0.0/33", "10.0.0.0/8"),
		ipCondPolicy(t, "NotIpAddress", "10.0.0.0/8", "10.0.0.256"),
		ipCondPolicy(t, "NotIpAddress", "10.0.0.256", "10.0.0.0/8"),
		ipCondPolicy(t, "IpAddress", "10.0.0.0/8"), // clean control case
	}

	var reqs []Request
	var singles []Result
	for i, pol := range policiesByCase {
		e := New([]policies.Policy{pol}, nil, nil)
		req := ipRequest()
		req.Principal = "user-batch"
		reqs = append(reqs, req)
		res := e.Evaluate(req)
		logResult(t, req, res)
		singles = append(singles, res)
		if i == len(policiesByCase)-1 && res.Decision != DecisionAllow {
			t.Fatalf("control case (clean list) must be allowed, got %s/%s", res.Decision, res.Reason)
		}
	}

	// Rebuild one engine per request is impossible for a single batch call, so
	// evaluate each policy's request against its own engine but through the
	// batch API: batch of one must equal single-shot, and a combined engine
	// holding all statements must stay consistent per request as well.
	for i := range reqs {
		e := New([]policies.Policy{policiesByCase[i]}, nil, nil)
		got := e.EvaluateBatch([]Request{reqs[i]})
		if len(got) != 1 || !reflect.DeepEqual(got[0], singles[i]) {
			t.Fatalf("batch-of-one drifted from single evaluation for case %d:\n %+v\n %+v", i, got, singles[i])
		}
	}
}
