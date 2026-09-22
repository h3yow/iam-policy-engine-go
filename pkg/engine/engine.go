package engine

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/h3yow/iam-policy-engine-go/pkg/policy"
)

// Engine evaluates requests against a fixed, immutable set of policy
// documents. Create one with New, then call Evaluate.
type Engine struct {
	identity []*policy.Document
	boundary []*policy.Document
	session  []*policy.Document
}

// Option configures an Engine at construction time.
type Option func(*Engine)

// New constructs an Engine from the supplied documents. Documents are copied
// and sorted into a canonical order, so callers may pass documents in any
// order and repeat statements freely: the result is always identical.
func New(identity, boundary, session []*policy.Document, opts ...Option) *Engine {
	e := &Engine{
		identity: canonicalize(identity, policy.SourceIdentity),
		boundary: canonicalize(boundary, policy.SourceBoundary),
		session:  canonicalize(session, policy.SourceSession),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// canonicalize stamps provenance, removes duplicate documents (same ID
// within a layer) and sorts by ID. Statements are scanned in their given
// order. Together these guarantee that policy order and repeated rules can
// never change the verdict or the set of matched rules.
func canonicalize(docs []*policy.Document, t policy.SourceType) []*policy.Document {
	indexByID := make(map[string]int, len(docs))
	out := make([]*policy.Document, 0, len(docs))
	for _, d := range docs {
		d.Source = policy.Source{Type: t, Name: d.ID}
		key := string(t) + "/" + d.ID
		if pos, ok := indexByID[key]; ok {
			// A repeated ID must repeat the same content; otherwise the
			// "canonical" document would depend on order.
			if !reflect.DeepEqual(out[pos].Statements, d.Statements) {
				panic(fmt.Sprintf("engine: duplicate policy id %q with different content", d.ID))
			}
			continue
		}
		indexByID[key] = len(out)
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return i < j
	})
	return out
}

// Credentials carries credential validity information for a request.
type Credentials struct {
	AccessKeyID string
	ExpiresAt   wallClock // zero value means "does not expire"
}

// Evaluate decides whether the request described by ctx is allowed.
// creds may be nil (or carry a zero ExpiresAt) for long-lived credentials.
//
// The evaluation order is fixed and matches the documented decision model:
//
//  1. Request-context completeness (missing action/resource => deny).
//  2. Credential validity (expired credentials => deny).
//  3. Explicit Deny in identity policies wins over everything.
//  4. At least one identity Allow must match.
//  5. Permission boundary must allow (only ever tightens).
//  6. Session policy must allow (only ever tightens).
//
// Any condition error inside a matching statement fails closed and is
// reported with its distinguishable reason.
func (e *Engine) Evaluate(ctx *policy.RequestContext, creds *Credentials) *Evaluation {
	if ctx == nil || ctx.Action == "" || ctx.Resource == "" {
		return &Evaluation{
			Decision:   DecisionDeny,
			DenyReason: ReasonContextMissing,
			Detail:     "request context, action and resource are all required",
		}
	}
	if creds != nil && !creds.ExpiresAt.IsZero() {
		now := ctx.Now
		if now.IsZero() {
			now = currentTime()
		}
		if !now.Before(creds.ExpiresAt) {
			return &Evaluation{
				Decision:   DecisionDeny,
				DenyReason: ReasonCredentialsExpired,
				Detail: fmt.Sprintf("credentials expired at %s, current time %s",
					creds.ExpiresAt, now),
			}
		}
	}

	ev := &Evaluation{Decision: DecisionDeny}

	// 3. Identity explicit deny.
	scan := e.scan(ctx, e.identity)
	ev.MatchedRules = append(ev.MatchedRules, scan.matched...)
	if scan.condErr != nil {
		return ev.denyCondition(scan.condErr)
	}
	if scan.deny {
		ev.DenyReason = ReasonExplicitDeny
		ev.Detail = fmt.Sprintf("explicit deny in identity policy %q", scan.denyRule.Source.Name)
		return ev
	}

	// 4. Identity allow; without one the default is deny.
	if !scan.allow {
		ev.DenyReason = ReasonNoMatch
		ev.Detail = "no identity policy statement allowed the request"
		return ev
	}

	// 5. Permission boundary: must independently allow.
	if len(e.boundary) > 0 {
		b := e.scan(ctx, e.boundary)
		ev.MatchedRules = append(ev.MatchedRules, b.matched...)
		if b.condErr != nil {
			return ev.denyCondition(b.condErr)
		}
		if b.deny {
			ev.DenyReason = ReasonBoundaryDeny
			ev.Detail = fmt.Sprintf("explicit deny in permission boundary %q", b.denyRule.Source.Name)
			return ev
		}
		if !b.allow {
			ev.DenyReason = ReasonBoundaryNoMatch
			ev.Detail = "request is not permitted by the permission boundary"
			return ev
		}
	}

	// 6. Session policy: must independently allow.
	if len(e.session) > 0 {
		s := e.scan(ctx, e.session)
		ev.MatchedRules = append(ev.MatchedRules, s.matched...)
		if s.condErr != nil {
			return ev.denyCondition(s.condErr)
		}
		if s.deny {
			ev.DenyReason = ReasonSessionDeny
			ev.Detail = fmt.Sprintf("explicit deny in session policy %q", s.denyRule.Source.Name)
			return ev
		}
		if !s.allow {
			ev.DenyReason = ReasonSessionNoMatch
			ev.Detail = "request is not permitted by the session policy"
			return ev
		}
	}

	ev.Decision = DecisionAllow
	return ev
}

func (ev *Evaluation) denyCondition(err *policy.ConditionError) *Evaluation {
	ev.Decision = DecisionDeny
	ev.DenyReason = ReasonConditionError
	ev.ConditionFail = err
	ev.Detail = err.Error()
	return ev
}

// layerOutcome is what scanning one policy layer (identity / boundary /
// session) produces.
type layerOutcome struct {
	matched   []MatchedRule // every action+resource-matching statement
	allow     bool
	deny      bool
	denyFound bool
	denyRule  MatchedRule
	condErr   *policy.ConditionError
}

// scan walks a layer in canonical document/statement order. The first
// condition error encountered wins (deterministic due to the ordering);
// among matching statements any Deny beats any Allow within the layer.
func (e *Engine) scan(ctx *policy.RequestContext, docs []*policy.Document) layerOutcome {
	out := layerOutcome{}
	for _, d := range docs {
		for i := range d.Statements {
			s := &d.Statements[i]
			am := policy.MatchAction(ctx.Action, *s)
			rm := policy.MatchResource(ctx.Resource, *s)
			if am == policy.MatchNoMatch || rm == policy.MatchNoMatch {
				continue
			}
			rule := MatchedRule{Source: d.Source, Index: i, Sid: s.Sid, Effect: s.Effect}
			out.matched = append(out.matched, rule)

			for ci := range s.Conditions {
				res, cerr := policy.EvalCondition(s.Conditions[ci], ctx)
				if res == policy.CondError {
					out.condErr = cerr
					return out
				}
				if res == policy.CondFalse {
					// Statement does not apply; do not let it allow OR deny.
					goto nextStatement
				}
			}

			if s.Effect == policy.EffectDeny {
				out.deny = true
				if !out.denyFound {
					out.denyFound = true
					out.denyRule = rule
				}
			} else {
				out.allow = true
			}
		nextStatement:
		}
	}
	return out
}
