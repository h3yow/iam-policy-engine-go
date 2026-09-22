// Package policy defines the policy document model shared by all policy
// sources (identity-based policies, permission boundaries, session policies).
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Effect is the outcome attached to an individual statement.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// Operator identifies a condition operator, e.g. StringEquals, IpAddress.
type Operator string

// Condition is a single condition block: one operator applied to one
// condition key against one or more values.
type Condition struct {
	Operator Operator
	Key      string
	Values   []string
}

// Statement is a single policy statement.
type Statement struct {
	Sid          string
	Effect       Effect
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Conditions   []Condition
}

// Document is a parsed policy document.
type Document struct {
	Version    string
	ID         string
	Source     Source // provenance, filled when a document is attached
	Statements []Statement
}

// Source describes where a policy document came from.
type Source struct {
	Type SourceType
	Name string
}

// SourceType identifies a policy source kind.
type SourceType string

const (
	SourceIdentity SourceType = "identity"
	SourceBoundary SourceType = "boundary"
	SourceSession  SourceType = "session"
)

// ---- JSON wire model -------------------------------------------------------

type jsonDocument struct {
	Version    string            `json:"Version"`
	ID         string            `json:"Id"`
	Statement  json.RawMessage   `json:"Statement"`
	Statements []json.RawMessage `json:"-"`
}

type jsonStatement struct {
	Sid         string                            `json:"Sid"`
	Effect      string                            `json:"Effect"`
	Action      flexibleStrings                   `json:"Action"`
	NotAction   flexibleStrings                   `json:"NotAction"`
	Resource    flexibleStrings                   `json:"Resource"`
	NotResource flexibleStrings                   `json:"NotResource"`
	Condition   map[string]map[string]flexStrings `json:"Condition"`
}

// flexibleStrings accepts a JSON string or a JSON array of strings.
type flexibleStrings []string

func (f *flexibleStrings) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*f = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("expected string or array of strings, got %s", string(data))
	}
	*f = many
	return nil
}

// flexStrings is an alias kept for readability in condition maps.
type flexStrings = flexibleStrings

// Parse parses a JSON policy document into a Document.
func Parse(raw []byte) (*Document, error) {
	var jd jsonDocument
	if err := json.Unmarshal(raw, &jd); err != nil {
		return nil, fmt.Errorf("policy parse: %w", err)
	}

	var raws []json.RawMessage
	// Statement may be a single object or an array; distinguish by the
	// first non-space byte rather than a probe unmarshal (a RawMessage
	// would happily swallow either shape).
	trimmed := bytes.TrimLeft(jd.Statement, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(jd.Statement, &arr); err != nil {
			return nil, fmt.Errorf("policy parse: Statement array: %w", err)
		}
		raws = arr
	} else {
		raws = []json.RawMessage{jd.Statement}
	}

	doc := &Document{Version: jd.Version, ID: jd.ID}
	for i, raw := range raws {
		var js jsonStatement
		if err := json.Unmarshal(raw, &js); err != nil {
			return nil, fmt.Errorf("policy parse: statement %d: %w", i, err)
		}
		st := Statement{
			Sid:          js.Sid,
			Effect:       Effect(js.Effect),
			Actions:      []string(js.Action),
			NotActions:   []string(js.NotAction),
			Resources:    []string(js.Resource),
			NotResources: []string(js.NotResource),
		}
		// Emit conditions in a fixed order (operator, then key) so that
		// documents differing only in JSON key order behave identically.
		for op, kv := range js.Condition {
			keys := make([]string, 0, len(kv))
			for k := range kv {
				keys = append(keys, k)
			}
			sortStrings(keys)
			for _, k := range keys {
				st.Conditions = append(st.Conditions, Condition{
					Operator: Operator(op),
					Key:      k,
					Values:   []string(kv[k]),
				})
			}
		}
		doc.Statements = append(doc.Statements, st)
	}

	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return doc, nil
}

// Validate performs structural validation of a document and returns the
// first error found, or nil when the document is well-formed.
func (d *Document) Validate() error {
	if len(d.Statements) == 0 {
		return fmt.Errorf("policy validate: document contains no statements")
	}
	for i := range d.Statements {
		s := &d.Statements[i]
		if s.Effect != EffectAllow && s.Effect != EffectDeny {
			return fmt.Errorf("policy validate: statement %d (%q): effect must be Allow or Deny, got %q", i, s.Sid, s.Effect)
		}
		if len(s.Actions) > 0 && len(s.NotActions) > 0 {
			return fmt.Errorf("policy validate: statement %d (%q): Action and NotAction are mutually exclusive", i, s.Sid)
		}
		if len(s.Actions) == 0 && len(s.NotActions) == 0 {
			return fmt.Errorf("policy validate: statement %d (%q): must declare Action or NotAction", i, s.Sid)
		}
		if len(s.Resources) > 0 && len(s.NotResources) > 0 {
			return fmt.Errorf("policy validate: statement %d (%q): Resource and NotResource are mutually exclusive", i, s.Sid)
		}
		// A statement without Resource/NotResource applies to every resource.
		if len(s.Resources) == 0 && len(s.NotResources) == 0 {
			s.Resources = []string{"*"}
		}
		for ci, c := range s.Conditions {
			if len(c.Values) == 0 {
				return fmt.Errorf("policy validate: statement %d (%q): condition %d on %q has no values", i, s.Sid, ci, c.Key)
			}
		}
	}
	return nil
}
