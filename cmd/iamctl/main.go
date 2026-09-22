// Command iamctl evaluates one authorization request against local policy
// documents, printing the decision, reason and matched rules.
//
// Usage:
//
//	iamctl -identity id.json [-boundary b.json] [-session s.json] -request req.json
//
// Exit code is 0 for Allow and 1 for Deny, so it can be wired into scripts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/engine"
	"github.com/h3yow/iam-policy-engine-go/pkg/policies"
)

func main() {
	var (
		idPath  = flag.String("identity", "", "identity policy JSON file")
		bdPath  = flag.String("boundary", "", "permission boundary policy JSON file (optional)")
		ssPath  = flag.String("session", "", "session policy JSON file (optional)")
		reqPath = flag.String("request", "", "request JSON file")
	)
	flag.Parse()

	if *idPath == "" || *reqPath == "" {
		fmt.Fprintln(os.Stderr, "both -identity and -request are required")
		flag.Usage()
		os.Exit(2)
	}

	identity, err := loadPolicies(policies.SourceIdentity, *idPath)
	must(err)
	boundary := []policies.Policy(nil)
	if *bdPath != "" {
		boundary, err = loadPolicies(policies.SourceBoundary, *bdPath)
		must(err)
	}
	session := []policies.Policy(nil)
	if *ssPath != "" {
		session, err = loadPolicies(policies.SourceSession, *ssPath)
		must(err)
	}

	req, err := loadRequest(*reqPath)
	must(err)

	eng := engine.New(identity, boundary, session)
	res := eng.Evaluate(req)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(jsonResult(res)))

	if res.Decision == engine.DecisionAllow {
		os.Exit(0)
	}
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func loadPolicies(src policies.Source, path string) ([]policies.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := policies.ParsePolicy(src, raw)
	if err != nil {
		return nil, err
	}
	return []policies.Policy{p}, nil
}

// requestDoc is the CLI request wire format.
type requestDoc struct {
	Principal string         `json:"principal"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Context   map[string]any `json:"context"`
	ExpiresAt string         `json:"expiresAt,omitempty"`
	IssuedAt  string         `json:"issuedAt,omitempty"`
	Now       string         `json:"now,omitempty"`
}

func loadRequest(path string) (engine.Request, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return engine.Request{}, err
	}
	var d requestDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return engine.Request{}, err
	}
	req := engine.Request{
		Principal: d.Principal,
		Action:    d.Action,
		Resource:  d.Resource,
		Context:   map[string]policies.Value{},
		Creds:     &policies.Credentials{AccessKeyID: "local-creds"},
	}
	if d.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, d.ExpiresAt)
		if err != nil {
			return req, fmt.Errorf("expiresAt: %w", err)
		}
		req.Creds.ExpiresAt = t
	}
	if d.IssuedAt != "" {
		t, err := time.Parse(time.RFC3339, d.IssuedAt)
		if err != nil {
			return req, fmt.Errorf("issuedAt: %w", err)
		}
		req.Creds.IssuedAt = t
	}
	if d.Now != "" {
		t, err := time.Parse(time.RFC3339, d.Now)
		if err != nil {
			return req, fmt.Errorf("now: %w", err)
		}
		req.Now = t
	}
	for k, v := range d.Context {
		req.Context[k] = wireValue(v)
	}
	return req, nil
}

// wireValue maps loose JSON context values into typed condition values.
func wireValue(v any) policies.Value {
	switch x := v.(type) {
	case string:
		return policies.StringV(x)
	case bool:
		return policies.BoolV(x)
	case float64:
		return policies.NumberV(x)
	case []any:
		vs := make([]policies.Value, 0, len(x))
		for _, e := range x {
			vs = append(vs, wireValue(e))
		}
		return policies.ListV(vs...)
	default:
		return policies.MissingV()
	}
}

type jsonOut struct {
	Decision   string                      `json:"decision"`
	Reason     string                      `json:"reason"`
	Detail     string                      `json:"detail"`
	Hits       []engine.RuleHit            `json:"hits"`
	Conditions []policies.ConditionOutcome `json:"conditions"`
}

func jsonResult(r engine.Result) jsonOut {
	return jsonOut{
		Decision:   string(r.Decision),
		Reason:     string(r.Reason),
		Detail:     r.Detail,
		Hits:       r.Hits,
		Conditions: r.Conditions,
	}
}
