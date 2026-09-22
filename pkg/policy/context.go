package policy

import "time"

// RequestContext carries all information known about an authorization
// request: the principal, the action/resource being requested and the
// condition keys (tags, IP, time, ...) available to condition operators.
type RequestContext struct {
	PrincipalARN string
	AccountID    string
	Action       string
	Resource     string
	Keys         map[string]Value
	Now          time.Time
}

// Value is a typed condition-key value.
type Value struct {
	Type ValueType
	Str  string
	Num  float64
	Bool bool
	Strs []string
}

// ValueType is the declared type of a condition-key value.
type ValueType string

const (
	TypeString ValueType = "String"
	TypeNumber ValueType = "Number"
	TypeBool   ValueType = "Bool"
	TypeDate   ValueType = "Date"
	TypeIP     ValueType = "IP"
)

// AsString returns the string representation used for comparison.
func (v Value) AsString() string {
	return ""
}
