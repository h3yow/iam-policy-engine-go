package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

func batchEngine(t testing.TB) *Engine {
	id := []policies.Policy{mustPolicy(t, policies.SourceIdentity, `{"Statement":[
		{"Sid":"s3-read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::app/*",
		 "Condition":{"IpAddress":{"src":["10.0.0.0/8"]},
		              "ForAllValues:StringEquals":{"tag":["prod","qa"]}}},
		{"Sid":"deny-secret","Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"},
		{"Sid":"list","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::app"}
	]}`)}
	return New(id, nil, nil)
}

func mkBatchReq(i int) Request {
	req := baseRequest("s3:GetObject", "arn:aws:s3:::app/o")
	switch i % 4 {
	case 0: // allowed by s3-read conditions
		req.Context = map[string]policies.Value{
			"src": policies.ListV(policies.StringV("10.1.2.3"), policies.StringV("10.4.5.6")),
			"tag": policies.ListV(policies.StringV("prod"), policies.StringV("qa")),
		}
	case 1: // denied by the secret-bucket explicit deny
		req.Resource = "arn:aws:s3:::secret/k"
	case 2: // condition fails: one IP outside 10/8
		req.Context = map[string]policies.Value{
			"src": policies.ListV(policies.StringV("10.1.2.3"), policies.StringV("192.0.2.1")),
			"tag": policies.ListV(policies.StringV("prod"), policies.StringV("dev")),
		}
	case 3: // condition fails: key missing on the only in-scope allow
		req.Context = map[string]policies.Value{}
	}
	return req
}

func TestEvaluateBatchMatchesSingleAndPreservesOrder(t *testing.T) {
	e := batchEngine(t)
	const n = 64
	reqs := make([]Request, n)
	for i := range reqs {
		reqs[i] = mkBatchReq(i)
	}

	batch := e.EvaluateBatch(reqs)
	if len(batch) != n {
		t.Fatalf("want %d results, got %d", n, len(batch))
	}
	for i, br := range batch {
		if br.Index != i {
			t.Fatalf("position %d carries index %d: results out of order", i, br.Index)
		}
		single := e.Evaluate(reqs[i])
		if !resultsEqual(single, br.Result) {
			t.Fatalf("batch result at %d differs from single evaluation:\nsingle=%+v\nbatch =%+v", i, single, br.Result)
		}
		t.Logf("BATCH[%d] action=%q resource=%q ctx=%v", i, reqs[i].Action, reqs[i].Resource, reqs[i].Context)
		for _, c := range br.Conditions {
			t.Logf("BATCH[%d] CONDITION op=%s key=%v success=%v reason=%s", i, c.Operator, c.Key, c.Success, c.Reason)
		}
		t.Logf("BATCH[%d] DECISION=%s reason=%s hits=%d", i, br.Decision, br.Reason, len(br.Hits))
	}

	// Spot-check expected decisions at each residue class.
	want := map[int]ReasonCode{0: ReasonAllowed, 1: ReasonExplicitDeny, 2: ReasonConditionFailed, 3: ReasonConditionFailed}
	for i := 0; i < 4; i++ {
		if batch[i].Reason != want[i] {
			t.Fatalf("request %d reason=%s want %s", i, batch[i].Reason, want[i])
		}
	}
}

func TestEvaluateBatchEmpty(t *testing.T) {
	if got := New(nil, nil, nil).EvaluateBatch(nil); len(got) != 0 {
		t.Fatalf("empty batch should return empty slice, got %d", len(got))
	}
}

func TestConcurrentEvaluationHasNoRaces(t *testing.T) {
	e := batchEngine(t)
	const goroutines = 32
	const perG = 40

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for k := 0; k < perG; k++ {
				req := mkBatchReq((g + k) % 4)
				res := e.Evaluate(req)
				batch := e.EvaluateBatch([]Request{req, mkBatchReq((g + k + 1) % 4)})
				if !resultsEqual(res, batch[0].Result) {
					t.Errorf("concurrent batch drift at g=%d k=%d", g, k)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestBatchContextIsolation(t *testing.T) {
	e := batchEngine(t)
	// Build requests whose list contexts share prefixes; ensure an earlier
	// request's values never leak into a later one's condition outcomes.
	reqs := []Request{
		mkBatchReq(0),
		mkBatchReq(3), // missing-key request in the middle
		mkBatchReq(2),
		mkBatchReq(0),
	}
	res := e.EvaluateBatch(reqs)
	if res[0].Reason != ReasonAllowed || res[3].Reason != ReasonAllowed {
		t.Fatalf("context leaked: outer requests should still be allowed, got %s / %s", res[0].Reason, res[3].Reason)
	}
	if res[1].Reason != ReasonConditionFailed {
		t.Fatalf("middle request missing-key outcome drifted: %s", res[1].Reason)
	}
	for i, br := range res {
		single := e.Evaluate(reqs[i])
		if !resultsEqual(single, br.Result) {
			t.Fatalf("isolation mismatch at %d", i)
		}
	}
}

// resultsEqual compares the decision-relevant fields. Hits/Conditions slices
// are already canonicalized (sorted+deduped) by finalize.
func resultsEqual(a, b Result) bool {
	if a.Decision != b.Decision || a.Reason != b.Reason || a.Detail != b.Detail {
		return false
	}
	if len(a.Hits) != len(b.Hits) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Hits {
		if hitKey(a.Hits[i]) != hitKey(b.Hits[i]) {
			return false
		}
	}
	for i := range a.Conditions {
		if a.Conditions[i] != b.Conditions[i] {
			return false
		}
	}
	return true
}

func BenchmarkEvaluateBatch1000(b *testing.B) {
	e := batchEngine(&testing.T{})
	reqs := make([]Request, 1000)
	for i := range reqs {
		reqs[i] = mkBatchReq(i)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		res := e.EvaluateBatch(reqs)
		if len(res) != 1000 {
			b.Fatal("wrong size")
		}
	}
}

func hitKey(h RuleHit) string {
	return fmt.Sprintf("%s|%s|%s|%v|%v|%v|%v",
		h.Source, h.Sid, h.Effect, h.NotAction, h.NotResource, h.Actions, h.Resources)
}

// keep time import referenced for future time-based batch tests
var _ = time.Now
