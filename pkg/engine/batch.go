package engine

import (
	"runtime"
	"sync"
)

// EvaluateBatch evaluates a batch of requests against the same policy set and
// returns one Result per request, in submission order: results[i] is the
// outcome for reqs[i] and is identical to calling Evaluate(reqs[i]) on its
// own.
//
// Requests are evaluated concurrently with a bounded worker pool (at most
// GOMAXPROCS in flight). The Engine holds no mutable evaluation state — every
// request gets its own hit/condition accumulators — so concurrent and batch
// evaluation can never drift from sequential single-shot results, and one
// request's context can never leak into another's. A nil or empty batch
// returns nil.
func (e *Engine) EvaluateBatch(reqs []Request) []Result {
	if len(reqs) == 0 {
		return nil
	}
	results := make([]Result, len(reqs))

	workers := runtime.GOMAXPROCS(0)
	if workers > len(reqs) {
		workers = len(reqs)
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = e.Evaluate(reqs[i])
			}
		}()
	}
	for i := range reqs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}
