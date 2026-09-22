package policies

// StatementMatch explains why a statement did or did not match a request.
type StatementMatch struct {
	Matched         bool
	ActionMatched   bool
	ResourceMatched bool
	Conditions      []ConditionOutcome
}

// Matches evaluates whether (action, resource, ctx) falls inside the statement.
//
// Action/resource scope honors the NotAction/NotResource exclusion form:
// a request matches a "Not*" scope only when it matches NONE of the listed
// patterns. Exclusion therefore never lets an unlisted action through when it
// is actually covered by an excluded pattern.
func (s Statement) Matches(action, resource string, ctx map[string]Value) StatementMatch {
	m := StatementMatch{}

	actionHit := MatchAny(s.Actions, action)
	m.ActionMatched = actionHit
	if s.UseNotAction {
		m.ActionMatched = !actionHit
	}

	resourceHit := MatchAny(s.Resources, resource)
	m.ResourceMatched = resourceHit
	if s.UseNotResource {
		m.ResourceMatched = !resourceHit
	}

	outcomes, condOK := EvaluateConditions(s.Conditions, ctx)
	m.Conditions = outcomes

	m.Matched = m.ActionMatched && m.ResourceMatched && condOK
	return m
}
