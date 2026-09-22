package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

// Decision is the final authorization conclusion.
type Decision string

const (
	DecisionAllow Decision = "Allow"
	DecisionDeny  Decision = "Deny"
)

// ReasonCode gives a machine-distinguishable explanation of the decision.
type ReasonCode string

const (
	ReasonAllowed             ReasonCode = "allowed"
	ReasonDefaultDeny         ReasonCode = "default_deny_no_matching_allow"
	ReasonExplicitDeny        ReasonCode = "explicit_deny"
	ReasonBoundaryDeny        ReasonCode = "permission_boundary_denied"
	ReasonSessionDeny         ReasonCode = "session_policy_denied"
	ReasonConditionFailed     ReasonCode = "condition_failed"
	ReasonInvalidRequest      ReasonCode = "invalid_request"
	ReasonCredentialsMissing  ReasonCode = "credentials_missing"
	ReasonCredentialsExpired  ReasonCode = "credentials_expired"
	ReasonCredentialsNotReady ReasonCode = "credentials_not_yet_valid"
)

// RuleHit records one statement that participated in the evaluation.
type RuleHit struct {
	Source      policies.Source
	Sid         string
	Effect      policies.Effect
	Actions     []string
	Resources   []string
	NotAction   bool
	NotResource bool
}

func (h RuleHit) key() string {
	return strings.Join([]string{
		string(h.Source), h.Sid, string(h.Effect),
		fmt.Sprintf("NA=%v/NR=%v", h.NotAction, h.NotResource),
		strings.Join(h.Actions, ","), strings.Join(h.Resources, ","),
	}, "|")
}

// Result is the full, explainable evaluation output.
type Result struct {
	Decision   Decision
	Reason     ReasonCode
	Detail     string
	Hits       []RuleHit
	Conditions []policies.ConditionOutcome
}

// Request is the authorization request context.
type Request struct {
	Principal string
	Action    string
	Resource  string
	Context   map[string]policies.Value
	Creds     *policies.Credentials
	Now       time.Time // evaluation instant; zero means time.Now
}

// Engine evaluates requests against a layered policy set.
type Engine struct {
	identity []policies.Policy
	boundary []policies.Policy
	session  []policies.Policy
	now      func() time.Time
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock overrides the clock (useful for testing credential expiry).
func WithClock(now func() time.Time) Option {
	return func(e *Engine) { e.now = now }
}

// New builds an Engine. Identity policies grant the baseline permissions;
// boundary and session policies can only tighten them, never loosen them.
func New(identity, boundary, session []policies.Policy, opts ...Option) *Engine {
	e := &Engine{identity: identity, boundary: boundary, session: session, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Evaluate runs the full decision pipeline for one request.
//
// Precedence (first match wins, evaluated top to bottom):
//  1. malformed request                -> deny
//  2. missing / not-valid / expired credentials -> deny
//  3. explicit Deny in ANY layer       -> deny (can never be overridden)
//  4. no Allow in identity policies    -> default deny
//  5. permission boundary does not allow -> deny
//  6. session policy does not allow    -> deny
//  7. otherwise                        -> allow
//
// Because every layer is fully scanned and matches are de-duplicated, the
// output is identical regardless of policy order or repeated statements.
func (e *Engine) Evaluate(req Request) Result {
	if err := validate(req); err != nil {
		return Result{Decision: DecisionDeny, Reason: ReasonInvalidRequest, Detail: err.Error()}
	}
	now := req.Now
	if now.IsZero() {
		now = e.now()
	}
	if r := checkCredentials(req.Creds, now); r != nil {
		return *r
	}

	ctx := req.Context
	var hits []RuleHit
	var condOutcomes []policies.ConditionOutcome

	identityDenies, identityAllows, idCondBlocked := collect(e.identity, req, ctx, &hits, &condOutcomes, false)
	if identityDenies {
		return finalize(DecisionDeny, ReasonExplicitDeny,
			"explicit Deny statement matched in identity policies; denies cannot be overridden",
			hits, condOutcomes)
	}
	if identityAllows == 0 {
		if idCondBlocked > 0 {
			return finalize(DecisionDeny, ReasonConditionFailed,
				"an in-scope identity Allow statement failed its conditions; see condition outcomes",
				hits, condOutcomes)
		}
		return finalize(DecisionDeny, ReasonDefaultDeny,
			"no identity policy statement allowed the request", hits, condOutcomes)
	}

	boundaryDenies, boundaryAllows, bdCondBlocked := collect(e.boundary, req, ctx, &hits, &condOutcomes, true)
	if boundaryDenies {
		return finalize(DecisionDeny, ReasonExplicitDeny,
			"explicit Deny statement matched in the permission boundary", hits, condOutcomes)
	}
	if boundaryAllows == 0 {
		if bdCondBlocked > 0 {
			return finalize(DecisionDeny, ReasonConditionFailed,
				"an in-scope boundary Allow statement failed its conditions; see condition outcomes",
				hits, condOutcomes)
		}
		return finalize(DecisionDeny, ReasonBoundaryDeny,
			"the permission boundary does not grant the action; boundaries can only tighten",
			hits, condOutcomes)
	}

	sessionDenies, sessionAllows, ssCondBlocked := collect(e.session, req, ctx, &hits, &condOutcomes, true)
	if sessionDenies {
		return finalize(DecisionDeny, ReasonExplicitDeny,
			"explicit Deny statement matched in the session policy", hits, condOutcomes)
	}
	if sessionAllows == 0 {
		if ssCondBlocked > 0 {
			return finalize(DecisionDeny, ReasonConditionFailed,
				"an in-scope session Allow statement failed its conditions; see condition outcomes",
				hits, condOutcomes)
		}
		return finalize(DecisionDeny, ReasonSessionDeny,
			"the session policy does not grant the action; session policies can only tighten",
			hits, condOutcomes)
	}

	return finalize(DecisionAllow, ReasonAllowed, "allowed by identity, boundary and session policies",
		hits, condOutcomes)
}

func validate(req Request) error {
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("request action must not be empty")
	}
	if strings.TrimSpace(req.Resource) == "" {
		return fmt.Errorf("request resource must not be empty")
	}
	return nil
}

// checkCredentials enforces credential time validity. A nil pointer means the
// caller presented no credentials at all and is refused outright.
func checkCredentials(c *policies.Credentials, now time.Time) *Result {
	if c == nil {
		return &Result{Decision: DecisionDeny, Reason: ReasonCredentialsMissing,
			Detail: "no credentials supplied with the request"}
	}
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
		return &Result{Decision: DecisionDeny, Reason: ReasonCredentialsExpired,
			Detail: fmt.Sprintf("credentials expired at %s (now %s)", c.ExpiresAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))}
	}
	if !c.IssuedAt.IsZero() && now.Before(c.IssuedAt) {
		return &Result{Decision: DecisionDeny, Reason: ReasonCredentialsNotReady,
			Detail: fmt.Sprintf("credentials are not valid before %s (now %s)", c.IssuedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))}
	}
	return nil
}

// collect scans every statement of one layer. It returns whether any Deny
// statement matched and the number of Allow statements that matched. Matched
// statements and condition outcomes are appended (de-duplicated later).
//
// optionalLayer marks boundary/session layers: when such a layer is absent
// entirely it imposes no constraint (deny=false, allows=1). The identity
// layer is mandatory and absent allows means a default deny.
// collect scans every statement of one layer. It returns:
//   - deny:        whether any Deny statement fully matched;
//   - allows:      number of Allow statements that fully matched;
//   - condBlocked: number of Allow statements that were in scope for
//     action+resource but failed their conditions (so the caller can emit
//     condition_failed instead of a generic default deny).
//
// Matched statements and condition outcomes are appended (de-duplicated later).
//
// optionalLayer marks boundary/session layers: when such a layer is absent
// entirely it imposes no constraint (deny=false, allows=1). The identity
// layer is mandatory and absent allows means a default deny.
func collect(layer []policies.Policy, req Request, ctx map[string]policies.Value,
	hits *[]RuleHit, conds *[]policies.ConditionOutcome, optionalLayer bool) (deny bool, allows, condBlocked int) {

	if len(layer) == 0 {
		if optionalLayer {
			return false, 1, 0
		}
		return false, 0, 0
	}

	for _, pol := range layer {
		for _, st := range pol.Statements {
			m := st.Matches(req.Action, req.Resource, ctx)
			// Record condition explanations whenever the statement was in scope
			// for action+resource, even if its conditions failed, so that
			// type-mismatch / missing-key / unknown-operator reasons are visible.
			if m.ActionMatched && m.ResourceMatched {
				*conds = append(*conds, m.Conditions...)
			}
			if !m.Matched {
				if st.Effect == policies.Allow && m.ActionMatched && m.ResourceMatched {
					condBlocked++
				}
				continue
			}
			*hits = append(*hits, RuleHit{
				Source:      pol.Source,
				Sid:         st.Sid,
				Effect:      st.Effect,
				Actions:     st.Actions,
				Resources:   st.Resources,
				NotAction:   st.UseNotAction,
				NotResource: st.UseNotResource,
			})
			switch st.Effect {
			case policies.Deny:
				deny = true
			case policies.Allow:
				allows++
			}
		}
	}
	return deny, allows, condBlocked
}

// finalize de-duplicates hits and condition outcomes and sorts them into a
// canonical order so equal inputs always produce equal Result values.
func finalize(d Decision, r ReasonCode, detail string, hits []RuleHit, conds []policies.ConditionOutcome) Result {
	seenHits := map[string]int{}
	var uniqHits []RuleHit
	for _, h := range hits {
		k := h.key()
		if _, ok := seenHits[k]; ok {
			continue
		}
		seenHits[k] = len(uniqHits)
		uniqHits = append(uniqHits, h)
	}
	sort.SliceStable(uniqHits, func(i, j int) bool { return uniqHits[i].key() < uniqHits[j].key() })

	seenC := map[string]int{}
	var uniqConds []policies.ConditionOutcome
	for _, c := range conds {
		k := string(c.Operator) + "|" + c.Key + "|" + string(c.Reason)
		if _, ok := seenC[k]; ok {
			continue
		}
		seenC[k] = 1
		uniqConds = append(uniqConds, c)
	}
	sort.SliceStable(uniqConds, func(i, j int) bool {
		a, b := uniqConds[i], uniqConds[j]
		if a.Operator != b.Operator {
			return a.Operator < b.Operator
		}
		return a.Key < b.Key
	})

	return Result{Decision: d, Reason: r, Detail: detail, Hits: uniqHits, Conditions: uniqConds}
}
