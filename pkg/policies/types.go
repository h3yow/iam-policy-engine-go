package policies

import "time"

// Effect is the conclusion produced by an individual policy statement.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Source identifies where a policy comes from. Precedence-relevant layering
// (identity / permission boundary / session) is represented separately; the
// source is carried only for explanation purposes.
type Source string

const (
	SourceIdentity Source = "identity"
	SourceBoundary Source = "boundary"
	SourceSession  Source = "session"
)

// Value is the typed representation of a condition key or comparison value.
// Exactly one of the fields (except Missing) is meaningful depending on Kind.
type Value struct {
	Kind    ValueKind
	Str     string
	Num     float64
	Bool    bool
	When    time.Time
	List    []Value
	Missing bool
}

// ValueKind enumerates the supported condition value types.
type ValueKind int

const (
	KindMissing ValueKind = iota
	KindString
	KindNumber
	KindBool
	KindTime
	KindList
)

// StringV / NumberV / BoolV / TimeV / ListV are constructors for typed values.
func StringV(s string) Value  { return Value{Kind: KindString, Str: s} }
func NumberV(n float64) Value { return Value{Kind: KindNumber, Num: n} }
func BoolV(b bool) Value      { return Value{Kind: KindBool, Bool: b} }
func TimeV(t time.Time) Value { return Value{Kind: KindTime, When: t} }
func ListV(vs ...Value) Value { return Value{Kind: KindList, List: vs} }
func MissingV() Value         { return Value{Kind: KindMissing, Missing: true} }

// Statement is a single normalized policy rule.
//
// When NotAction / NotResource were used in the wire document, the patterns
// are stored in Actions / Resources and the corresponding UseNot* flag is set.
// Matching then means "the request does NOT match any listed pattern".
type Statement struct {
	Sid            string
	Effect         Effect
	Actions        []string // patterns
	Resources      []string // patterns
	UseNotAction   bool
	UseNotResource bool
	Conditions     ConditionSet
}

// ConditionSet groups conditions by operator, e.g. {"StringEquals": {...}}.
type ConditionSet map[Operator]ConditionMap

// ConditionMap maps a condition key to the list of expected values.
type ConditionMap map[string][]Value

// Operator is a condition operator name such as StringEquals.
type Operator string

// Policy is one parsed policy document from a single source.
type Policy struct {
	Source     Source
	Statements []Statement
}

// Credentials describe the temporary credentials carried by a request.
type Credentials struct {
	AccessKeyID string
	IssuedAt    time.Time // optional; zero means unknown
	ExpiresAt   time.Time // zero means no expiry constraint
}
