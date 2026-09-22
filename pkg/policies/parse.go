package policies

import (
	"encoding/json"
	"fmt"
)

// ParsePolicy decodes a JSON policy document and normalizes it into a Policy
// tagged with the given source.
//
// Accepted wire shape (single object, "Statement" may also be one object):
//
//	{
//	  "Version": "2012-10-17",
//	  "Statement": [
//	    {
//	      "Sid": "read",
//	      "Effect": "Allow",
//	      "Action": ["s3:GetObject"],
//	      "Resource": ["arn:.../*"],
//	      "Condition": {"StringEquals": {"env": ["prod"]}}
//	    }
//	  ]
//	}
func ParsePolicy(src Source, raw []byte) (Policy, error) {
	var doc policyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Policy{}, fmt.Errorf("parse policy: invalid JSON: %w", err)
	}
	return normalize(src, doc)
}

// policyDoc is the wire representation of a policy document.
type policyDoc struct {
	Version    any             `json:"Version"`
	Statements json.RawMessage `json:"Statement"`
}

// statementDoc uses raw messages for fields whose wire shape is flexible
// (string or list of strings; arbitrary condition trees).
type statementDoc struct {
	Sid         string          `json:"Sid"`
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Condition   json.RawMessage `json:"Condition"`
}

func normalize(src Source, doc policyDoc) (Policy, error) {
	pol := Policy{Source: src}
	if len(doc.Statements) == 0 {
		return pol, nil
	}

	// Statement may be a single object or an array.
	var raws []json.RawMessage
	var one json.RawMessage
	if err := json.Unmarshal(doc.Statements, &raws); err != nil {
		if err2 := json.Unmarshal(doc.Statements, &one); err2 != nil {
			return Policy{}, fmt.Errorf("parse policy: Statement must be object or array: %w", err)
		}
		raws = []json.RawMessage{one}
	}

	for i, raw := range raws {
		var sd statementDoc
		if err := json.Unmarshal(raw, &sd); err != nil {
			return Policy{}, fmt.Errorf("parse policy: statement %d: %w", i, err)
		}
		st, err := normalizeStatement(sd)
		if err != nil {
			return Policy{}, fmt.Errorf("parse policy: statement %d (%q): %w", i, sd.Sid, err)
		}
		pol.Statements = append(pol.Statements, st)
	}
	return pol, nil
}

func normalizeStatement(sd statementDoc) (Statement, error) {
	st := Statement{Sid: sd.Sid}

	switch sd.Effect {
	case string(Allow):
		st.Effect = Allow
	case string(Deny):
		st.Effect = Deny
	default:
		return Statement{}, fmt.Errorf("unknown Effect %q (want Allow or Deny)", sd.Effect)
	}

	// Exactly one of Action/NotAction must be present.
	hasA, hasNA := len(sd.Action) > 0, len(sd.NotAction) > 0
	if hasA == hasNA {
		return Statement{}, fmt.Errorf("exactly one of Action/NotAction is required")
	}
	if hasA {
		acts, err := toStringSlice(sd.Action)
		if err != nil {
			return Statement{}, fmt.Errorf("Action: %w", err)
		}
		st.Actions = acts
	} else {
		acts, err := toStringSlice(sd.NotAction)
		if err != nil {
			return Statement{}, fmt.Errorf("NotAction: %w", err)
		}
		st.Actions, st.UseNotAction = acts, true
	}

	// Exactly one of Resource/NotResource must be present.
	hasR, hasNR := len(sd.Resource) > 0, len(sd.NotResource) > 0
	if hasR == hasNR {
		return Statement{}, fmt.Errorf("exactly one of Resource/NotResource is required")
	}
	if hasR {
		res, err := toStringSlice(sd.Resource)
		if err != nil {
			return Statement{}, fmt.Errorf("Resource: %w", err)
		}
		st.Resources = res
	} else {
		res, err := toStringSlice(sd.NotResource)
		if err != nil {
			return Statement{}, fmt.Errorf("NotResource: %w", err)
		}
		st.Resources, st.UseNotResource = res, true
	}

	if len(sd.Condition) > 0 {
		cset, err := parseCondition(sd.Condition)
		if err != nil {
			return Statement{}, fmt.Errorf("Condition: %w", err)
		}
		st.Conditions = cset
	}
	return st, nil
}

// toStringSlice accepts either a JSON string or a JSON array of strings.
func toStringSlice(raw json.RawMessage) ([]string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("must be string or []string: %w", err)
	}
	if len(arr) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	return arr, nil
}

// parseCondition decodes {"Operator": {"key": <scalar-or-list>}} into a
// ConditionSet of typed Values.
func parseCondition(raw json.RawMessage) (ConditionSet, error) {
	var groups map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, fmt.Errorf("must be {operator: {key: value}}: %w", err)
	}
	out := ConditionSet{}
	for op, m := range groups {
		cm := ConditionMap{}
		for key, vraw := range m {
			vs, err := parseValues(vraw)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", op, key, err)
			}
			cm[key] = vs
		}
		out[Operator(op)] = cm
	}
	return out, nil
}

// parseValues accepts a scalar or a list of scalars and infers the value type
// from JSON shape: bool -> Bool, number -> Number, RFC3339 string that parses
// as a time -> Time, otherwise String.
func parseValues(raw json.RawMessage) ([]Value, error) {
	var scalars []json.RawMessage
	var one json.RawMessage
	if err := json.Unmarshal(raw, &scalars); err != nil {
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			return nil, fmt.Errorf("value must be scalar or list: %w", err)
		}
		scalars = []json.RawMessage{one}
	}
	vs := make([]Value, 0, len(scalars))
	for _, sc := range scalars {
		v, err := parseScalar(sc)
		if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, nil
}

func parseScalar(raw json.RawMessage) (Value, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return BoolV(b), nil
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return NumberV(n), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return Value{}, fmt.Errorf("unsupported value %s", string(raw))
	}
	if t, err := parseTime(s); err == nil {
		return TimeV(t), nil
	}
	return StringV(s), nil
}
