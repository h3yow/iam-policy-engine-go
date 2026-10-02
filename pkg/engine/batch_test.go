package engine

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

// batchFixture builds an engine exercising every layer and the new
// multi-value / IP / ARN condition capabilities.
func batchFixture(t *testing.T) *Engine {
	t.Helper()
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"tagged-read","Effect":"Allow","Action":"s3:GetObject","Resource":"*",
		 "Condition":{"ForAllValues:StringEquals":{"env":["prod","staging"]}}},
		{"Sid":"net-read","Effect":"Allow","Action":"s3:GetObject","Resource":"*",
		 "Condition":{"IpAddress":{"sourceIp":["10.0.0.0/8","2001:db8::/32"]}}},
		{"Sid":"deny-secret-arn","Effect":"Deny","Action":"s3:*","Resource":"*",
		 "Condition":{"ArnLike":{"targetArn":"arn:aws:s3:::secret/*"}}},
		{"Sid":"deny-offnet","Effect":"Deny","Action":"s3:*","Resource":"*",
		 "Condition":{"NotIpAddress":{"sourceIp":["10.0.0.0/8","2001:db8::/32"]}}}
	]}`)}
	boundary := []policies.Policy{mustPolicy(t, policies.SourceBoundary, `{"Statement":[
		{"Sid":"reads","Effect":"Allow","Action":"s3:Get*","Resource":"*"}
	]}`)}
	return New(id, boundary, nil)
}

func batchRequests() []Request {
	mk := func(i int, ctx map[string]policies.Value) Request {
		return Request{
			Principal: fmt.Sprintf("user-%d", i),
			Action:    "s3:GetObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::bucket/obj-%d", i),
			Context:   ctx,
			Creds:     credsValid(),
			Now:       fixedNow,
		}
	}
	return []Request{
		// 0: allowed via tag condition (ForAllValues over multi-value key)
		mk(0, map[string]policies.Value{
			"env":      policies.ListV(policies.StringV("prod"), policies.StringV("staging")),
			"sourceIp": policies.StringV("10.1.2.3"),
		}),
		// 1: allowed via IP condition (IPv6)
		mk(1, map[string]policies.Value{
			"env":      policies.StringV("dev"),
			"sourceIp": policies.StringV("2001:db8::42"),
		}),
		// 2: denied — off-network explicit deny (NotIpAddress whole-set)
		mk(2, map[string]policies.Value{
			"env":      policies.StringV("prod"),
			"sourceIp": policies.StringV("203.0.113.9"),
		}),
		// 3: denied — secret ARN exclusion
		mk(3, map[string]policies.Value{
			"env":       policies.StringV("prod"),
			"sourceIp":  policies.StringV("10.9.9.9"),
			"targetArn": policies.StringV("arn:aws:s3:::secret/keys"),
		}),
		// 4: denied — ForAllValues fails on mixed tag set
		mk(4, map[string]policies.Value{
			"env":      policies.ListV(policies.StringV("prod"), policies.StringV("dev")),
			"sourceIp": policies.StringV("192.168.0.1"),
		}),
		// 5: denied — condition key missing entirely
		mk(5, map[string]policies.Value{}),
	}
}

func TestEvaluateBatchMatchesSingleEvaluation(t *testing.T) {
	e := batchFixture(t)
	reqs := batchRequests()

	batch := e.EvaluateBatch(reqs)
	if len(batch) != len(reqs) {
		t.Fatalf("batch returned %d results for %d requests", len(batch), len(reqs))
	}

	wantReasons := []ReasonCode{
		ReasonAllowed,       // 0
		ReasonAllowed,       // 1
		ReasonExplicitDeny,  // 2
		ReasonExplicitDeny,  // 3
		ReasonExplicitDeny,  // 4 (off-net deny fires as well)
		ReasonConditionFailed, // 5
	}
	for i, res := range batch {
		logResult(t, reqs[i], res)
		if res.Reason != wantReasons[i] {
			t.Fatalf("request %d: reason=%s want %s", i, res.Reason, wantReasons[i])
		}
		// Each batch result must be identical to a standalone evaluation.
		single := e.Evaluate(reqs[i])
		if !reflect.DeepEqual(res, single) {
			t.Fatalf("request %d: batch result differs from single evaluation:\nbatch=%+v\nsingle=%+v", i, res, single)
		}
	}
}

func TestEvaluateBatchEmpty(t *testing.T) {
	e := batchFixture(t)
	if got := e.EvaluateBatch(nil); got != nil {
		t.Fatalf("nil batch must return nil, got %v", got)
	}
	if got := e.EvaluateBatch([]Request{}); got != nil {
		t.Fatalf("empty batch must return nil, got %v", got)
	}
}

func TestConcurrentEvaluationIsRaceFreeAndStable(t *testing.T) {
	e := batchFixture(t)
	reqs := batchRequests()
	// Expected results computed once, sequentially.
	want := make([]Result, len(reqs))
	for i, r := range reqs {
		want[i] = e.Evaluate(r)
	}

	const goroutines = 32
	const rounds = 20
	var wg sync.WaitGroup
	errs := make(chan string, goroutines*rounds)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				// Mix single evaluations and batch evaluations on the shared engine.
				i := (g + round) % len(reqs)
				if got := e.Evaluate(reqs[i]); !reflect.DeepEqual(got, want[i]) {
					errs <- fmt.Sprintf("goroutine %d round %d: single eval drifted for request %d", g, round, i)
				}
				if round%5 == 0 {
					got := e.EvaluateBatch(reqs)
					for i := range want {
						if !reflect.DeepEqual(got[i], want[i]) {
							errs <- fmt.Sprintf("goroutine %d round %d: batch eval drifted for request %d", g, round, i)
						}
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}

func TestBatchContextsDoNotBleedAcrossRequests(t *testing.T) {
	e := batchFixture(t)
	// Interleave requests whose contexts would change each other's outcome if
	// any state leaked between evaluations.
	onNet := map[string]policies.Value{"sourceIp": policies.StringV("10.0.0.5"), "env": policies.StringV("prod")}
	offNet := map[string]policies.Value{"sourceIp": policies.StringV("198.51.100.7"), "env": policies.StringV("prod")}

	reqs := make([]Request, 0, 64)
	for i := 0; i < 32; i++ {
		ctx := onNet
		if i%2 == 1 {
			ctx = offNet
		}
		reqs = append(reqs, Request{
			Principal: "user-x", Action: "s3:GetObject",
			Resource: "arn:aws:s3:::bucket/o", Context: ctx,
			Creds: credsValid(), Now: fixedNow,
		})
	}
	got := e.EvaluateBatch(reqs)
	for i, res := range got {
		wantReason := ReasonAllowed
		if i%2 == 1 {
			wantReason = ReasonExplicitDeny // off-net deny
		}
		if res.Reason != wantReason {
			t.Fatalf("request %d: reason=%s want %s (context bleed suspected)", i, res.Reason, wantReason)
		}
	}
}
