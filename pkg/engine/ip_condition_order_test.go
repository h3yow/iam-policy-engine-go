package engine

import (
	"reflect"
	"testing"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

// These tests reproduce the gateway / inspection scenario: a network-location
// condition key lists several expected networks and one entry is a typo
// (prefix length out of range, bad address literal). The decision and the
// reported reason must be identical no matter where the malformed member sits
// in the JSON array.

// ipPolicyDoc builds an identity policy whose sole statement gates
// s3:GetObject on an IpAddress / NotIpAddress condition over the given
// ordered list of expected networks.
func ipPolicyDoc(sid, op string, expected []string) string {
	// Render the expected list as a JSON array without reordering.
	lit := "["
	for i, e := range expected {
		if i > 0 {
			lit += ","
		}
		lit += "\"" + e + "\""
	}
	lit += "]"
	return `{"Statement":[{"Sid":"` + sid + `","Effect":"Allow","Action":"s3:GetObject","Resource":"*",` +
		`"Condition":{"` + op + `":{"sourceIp":` + lit + `}}}]}`
}

// TestIpConditionInvalidExpectedMemberOrderIndependent runs the SAME request
// against two policies that differ ONLY in the order of the expected networks
// (legal matching member first vs. malformed member first), for both IpAddress
// and NotIpAddress. Both orders must deny with condition_failed and a
// condition_invalid_value outcome.
func TestIpConditionInvalidExpectedMemberOrderIndependent(t *testing.T) {
	orders := map[string][]string{
		"legal-match-first": {"10.0.0.0/8", "10.0.0.0/33", "10.0.0.256"},
		"illegal-first":     {"10.0.0.256", "10.0.0.0/33", "10.0.0.0/8"},
	}
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"sourceIp": policies.StringV("10.0.0.7")}

	for _, op := range []string{"IpAddress", "NotIpAddress"} {
		t.Run(op, func(t *testing.T) {
			results := map[string]Result{}
			for orderName, members := range orders {
				id := []policies.Policy{mustPolicy(t, policies.SourceIdentity,
					ipPolicyDoc("net-gate", op, members))}
				e := New(id, nil, nil)
				res := e.Evaluate(req)
				t.Logf("REQUEST order=%s op=%s principal=%q action=%q resource=%q context=%v",
					orderName, op, req.Principal, req.Action, req.Resource, req.Context)
				for _, h := range res.Hits {
					t.Logf("HIT RULE: source=%s sid=%s effect=%s", h.Source, h.Sid, h.Effect)
				}
				for _, c := range res.Conditions {
					t.Logf("CONDITION: op=%s key=%s success=%v reason=%s", c.Operator, c.Key, c.Success, c.Reason)
				}
				t.Logf("DECISION order=%s: %s reason=%s detail=%q", orderName, res.Decision, res.Reason, res.Detail)

				if res.Decision != DecisionDeny || res.Reason != ReasonConditionFailed {
					t.Fatalf("%s/%s: got %s/%s, want Deny/condition_failed (typo must fail closed)",
						op, orderName, res.Decision, res.Reason)
				}
				if !hasCondReason(res, policies.CondInvalidValue) {
					t.Fatalf("%s/%s: want a condition_invalid_value outcome, got %+v",
						op, orderName, res.Conditions)
				}
				results[orderName] = res
			}
			// Decision, reason code and every condition outcome must be identical
			// across permutations.
			a, b := results["legal-match-first"], results["illegal-first"]
			if a.Decision != b.Decision || a.Reason != b.Reason ||
				!reflect.DeepEqual(a.Conditions, b.Conditions) {
				t.Fatalf("%s: result drifted with list order:\n%+v\nvs\n%+v", op, a, b)
			}
		})
	}
}

// TestIpConditionNegatedInvalidMemberStillDenies focuses on the negated form
// when the legal member does NOT contain the actual address: previously the
// malformed member could be skipped and the clause passed, admitting a request
// that the typo'd exclusion set cannot vouch for. Both orders must deny.
func TestIpConditionNegatedInvalidMemberStillDenies(t *testing.T) {
	orders := map[string][]string{
		"legal-first":   {"10.0.0.0/8", "2001:db8::/129"},
		"illegal-first": {"2001:db8::/129", "10.0.0.0/8"},
	}
	req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
	req.Context = map[string]policies.Value{"sourceIp": policies.StringV("8.8.8.8")}

	var ref Result
	for orderName, members := range orders {
		id := []policies.Policy{mustPolicy(t, policies.SourceIdentity,
			ipPolicyDoc("net-gate-not", "NotIpAddress", members))}
		res := New(id, nil, nil).Evaluate(req)
		logResult(t, req, res)
		if res.Decision != DecisionDeny || res.Reason != ReasonConditionFailed ||
			!hasCondReason(res, policies.CondInvalidValue) {
			t.Fatalf("order=%s: got %s/%s conds=%+v, want Deny/condition_failed with invalid_value",
				orderName, res.Decision, res.Reason, res.Conditions)
		}
		if orderName == "legal-first" {
			ref = res
		} else if !reflect.DeepEqual(ref.Conditions, res.Conditions) {
			t.Fatalf("NotIpAddress condition outcomes drifted across orders:\n%+v\n%+v", ref.Conditions, res.Conditions)
		}
	}
}

// TestIpConditionOrderBatchParity runs both policy orderings through the
// concurrent batch path and checks every batch result equals the standalone
// result — execution order / concurrency must not change conclusions.
func TestIpConditionOrderBatchParity(t *testing.T) {
	mkReqs := func() []Request {
		reqs := make([]Request, 8)
		for i := range reqs {
			r := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
			r.Principal = "user-batch"
			r.Context = map[string]policies.Value{"sourceIp": policies.StringV("10.0.0.7")}
			reqs[i] = r
		}
		return reqs
	}
	for _, members := range [][]string{
		{"10.0.0.0/8", "10.0.0.0/33"},
		{"10.0.0.0/33", "10.0.0.0/8"},
	} {
		id := []policies.Policy{mustPolicy(t, policies.SourceIdentity,
			ipPolicyDoc("net-gate", "IpAddress", members))}
		e := New(id, nil, nil)
		reqs := mkReqs()
		batch := e.EvaluateBatch(reqs)
		for i, res := range batch {
			single := e.Evaluate(reqs[i])
			if !reflect.DeepEqual(res, single) {
				t.Fatalf("members=%v request %d: batch drifted from single:\n%+v\n%+v",
					members, i, res, single)
			}
			if res.Decision != DecisionDeny || res.Reason != ReasonConditionFailed {
				t.Fatalf("members=%v request %d: got %s/%s, want Deny/condition_failed",
					members, i, res.Decision, res.Reason)
			}
		}
	}
}

// TestIpConditionAllLegalMultiExpectedStillAllows guards compatibility: a
// multi-member list without typos keeps admitting a request whose address is
// inside one member, regardless of member order.
func TestIpConditionAllLegalMultiExpectedStillAllows(t *testing.T) {
	for _, members := range [][]string{
		{"10.0.0.0/8", "2001:db8::/32"},
		{"2001:db8::/32", "10.0.0.0/8"},
	} {
		id := []policies.Policy{mustPolicy(t, policies.SourceIdentity,
			ipPolicyDoc("net-gate", "IpAddress", members))}
		e := New(id, nil, nil)
		req := baseRequest("s3:GetObject", "arn:aws:s3:::b/o")
		req.Context = map[string]policies.Value{"sourceIp": policies.StringV("2001:db8::9")}
		res := e.Evaluate(req)
		logResult(t, req, res)
		if res.Decision != DecisionAllow || res.Reason != ReasonAllowed {
			t.Fatalf("members=%v: got %s/%s, want Allow/allowed", members, res.Decision, res.Reason)
		}
	}
}
