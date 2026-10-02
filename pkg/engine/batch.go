package engine

import (
	"runtime"
	"sync"
)

// BatchResult is one entry of an EvaluateBatch response.
type BatchResult struct {
	// Index is the zero-based position of the request in the submitted batch,
	// so callers may correlate results even if they re-sort the output.
	Index int
	Result
}

// EvaluateBatch evaluates a batch of requests against the same layered policy
// set and returns one result PER REQUEST, IN SUBMISSION ORDER.
//
// Guarantees:
//
//   - results[i] is exactly the Result Evaluate(requests[i]) would produce in
//     isolation — batching never changes a decision, reason, hits or condition
//     outcomes;
//   - requests are independent: the context of one request can never influence
//     another (each evaluation works only on its own values; policies are
//     read-only);
//   - evaluation is safe for concurrent use of the same *Engine. Workers share
//     the policy slices but never mutate them, and each request writes only to
//     its own pre-indexed slot, so there is no shared mutable state;
//   - concurrency is bounded (GOMAXPROCS workers) so very large batches do
//     not spawn unbounded goroutines.
func (e *Engine) EvaluateBatch(requests []Request) []BatchResult {
	results := make([]BatchResult, len(requests))
	if len(requests) == 0 {
		return results
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > len(requests) {
		workers = len(requests)
	}

	type job struct{ idx int }
	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Every per-request value (hits, condition outcomes, context)
				// is allocated fresh inside Evaluate; nothing leaks between
				// requests.
				results[j.idx] = BatchResult{Index: j.idx, Result: e.Evaluate(requests[j.idx])}
			}
		}()
	}
	for i := range requests {
		jobs <- job{i}
	}
	close(jobs)
	wg.Wait()
	return results
}
