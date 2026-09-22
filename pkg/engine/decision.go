// Package engine combines policy documents from multiple sources and
// evaluates authorization requests with deterministic, explainable results.
package engine

import (
	"github.com/h3yow/iam-policy-engine-go/pkg/policy"
)

// Decision is the final allow/deny verdict.
type Decision string

const (
	DecisionAllow Decision = "Allow"
	DecisionDeny  Decision = "Deny"
)

// DenyReason is the distinguishable cause of a deny verdict.
type DenyReason string

const (
	ReasonExplicitDeny       DenyReason = "ExplicitDeny"
	ReasonNoMatch            DenyReason = "DefaultDeny.NoMatch"
	ReasonBoundaryDeny       DenyReason = "PermissionBoundary.ExplicitDeny"
	ReasonBoundaryNoMatch    DenyReason = "PermissionBoundary.DefaultDeny"
	ReasonSessionDeny        DenyReason = "SessionPolicy.ExplicitDeny"
	ReasonSessionNoMatch     DenyReason = "SessionPolicy.DefaultDeny"
	ReasonCredentialsExpired DenyReason = "CredentialsExpired"
	ReasonContextMissing     DenyReason = "ContextMissing"
	ReasonConditionError     DenyReason = "ConditionError"
)

// MatchedRule records one statement that fired during evaluation.
type MatchedRule struct {
	Source policy.Source
	Index  int
	Sid    string
	Effect policy.Effect
}

// Evaluation is the fully explained result of evaluating one request.
type Evaluation struct {
	Decision      Decision
	DenyReason    DenyReason
	MatchedRules  []MatchedRule
	ConditionFail *policy.ConditionError
	Detail        string
}

// IsAllowed is a convenience accessor.
func (e *Evaluation) IsAllowed() bool { return e.Decision == DecisionAllow }
