package policy

import "testing"

func ctxWith(keys map[string]Value) *RequestContext {
	return &RequestContext{Action: "a", Resource: "r", Keys: keys}
}

func TestStringOperators(t *testing.T) {
	c := Condition{Operator: "StringEquals", Key: "k", Values: []string{"alice", "bob"}}
	ctx := ctxWith(map[string]Value{"k": {Type: TypeString, Str: "bob"}})
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("StringEquals any-value should be true")
	}

	c.Operator = "StringNotEquals"
	if r, _ := EvalCondition(c, ctx); r != CondFalse {
		t.Error("StringNotEquals against a matching value should be false")
	}

	c.Operator = "StringLike"
	c.Values = []string{"al*"}
	if r, _ := EvalCondition(c, ctx); r != CondFalse {
		t.Error("bob must not match glob al*")
	}
	ctx.Keys["k"] = Value{Type: TypeString, Str: "alice"}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("alice should match glob al*")
	}

	c.Operator = "StringEqualsIgnoreCase"
	c.Values = []string{"ALICE"}
	ctx.Keys["k"] = Value{Type: TypeString, Str: "alice"}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("case-insensitive equals should be true")
	}
}

func TestNumericOperators(t *testing.T) {
	ctx := ctxWith(map[string]Value{"age": {Type: TypeNumber, Num: 21}})
	cases := []struct {
		op   Operator
		val  string
		want ConditionResult
	}{
		{"NumericGreaterThan", "18", CondTrue},
		{"NumericGreaterThanEquals", "21", CondTrue},
		{"NumericLessThan", "21", CondFalse},
		{"NumericEquals", "21", CondTrue},
		{"NumericNotEquals", "22", CondTrue},
	}
	for _, tc := range cases {
		c := Condition{Operator: tc.op, Key: "age", Values: []string{tc.val}}
		if r, _ := EvalCondition(c, ctx); r != tc.want {
			t.Errorf("%s %s = %v, want %v", tc.op, tc.val, r, tc.want)
		}
	}

	// Non-numeric key value.
	c := Condition{Operator: "NumericEquals", Key: "age", Values: []string{"21"}}
	badCtx := ctxWith(map[string]Value{"age": {Type: TypeString, Str: "21"}})
	r, err := EvalCondition(c, badCtx)
	if r != CondError || err.Reason != CondErrTypeMismatch {
		t.Errorf("want TypeMismatch, got %v %v", r, err)
	}

	// Non-numeric comparison value.
	c = Condition{Operator: "NumericEquals", Key: "age", Values: []string{"xx"}}
	if r, err = EvalCondition(c, ctx); r != CondError || err.Reason != CondErrInvalidValue {
		t.Errorf("want InvalidValue, got %v %v", r, err)
	}
}

func TestBoolOperator(t *testing.T) {
	ctx := ctxWith(map[string]Value{"secure": {Type: TypeBool, Bool: true}})
	c := Condition{Operator: "Bool", Key: "secure", Values: []string{"true"}}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("Bool true=true should be true")
	}
	c.Values = []string{"false"}
	if r, _ := EvalCondition(c, ctx); r != CondFalse {
		t.Error("Bool true vs false should be false")
	}
}

func TestIPOperator(t *testing.T) {
	ctx := ctxWith(map[string]Value{"ip": {Type: TypeString, Str: "192.0.2.7"}})
	c := Condition{Operator: "IpAddress", Key: "ip", Values: []string{"192.0.2.0/24"}}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("IP inside CIDR should be true")
	}
	c.Values = []string{"10.0.0.0/8"}
	if r, _ := EvalCondition(c, ctx); r != CondFalse {
		t.Error("IP outside CIDR should be false")
	}
	c.Operator = "NotIpAddress"
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("NotIpAddress outside CIDR should be true")
	}
	c.Values = []string{"not-a-cidr"}
	if r, err := EvalCondition(c, ctx); r != CondError || err.Reason != CondErrInvalidValue {
		t.Errorf("want InvalidValue for bad CIDR, got %v %v", r, err)
	}
}

func TestDateOperator(t *testing.T) {
	// key epoch = 1000
	ctx := ctxWith(map[string]Value{"t": {Type: TypeDate, Num: 1000}})
	c := Condition{Operator: "DateGreaterThan", Key: "t", Values: []string{"999"}}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("date compare wrong")
	}
	c.Values = []string{"bad"}
	if r, err := EvalCondition(c, ctx); r != CondError || err.Reason != CondErrInvalidValue {
		t.Errorf("want InvalidValue for bad epoch, got %v %v", r, err)
	}
	ctx2 := ctxWith(map[string]Value{"t": {Type: TypeString, Str: "1000"}})
	c.Values = []string{"999"}
	if r, err := EvalCondition(c, ctx2); r != CondError || err.Reason != CondErrTypeMismatch {
		t.Errorf("want TypeMismatch for string key, got %v %v", r, err)
	}
}

func TestNullOperator(t *testing.T) {
	ctx := ctxWith(map[string]Value{"present": {Type: TypeString, Str: "x"}})
	c := Condition{Operator: "Null", Key: "absent", Values: []string{"true"}}
	if r, _ := EvalCondition(c, ctx); r != CondTrue {
		t.Error("Null true on absent key should be true (not a missing-key error)")
	}
	c.Key = "present"
	if r, _ := EvalCondition(c, ctx); r != CondFalse {
		t.Error("Null true on present key should be false")
	}
}

func TestMissingKeyDistinguishable(t *testing.T) {
	c := Condition{Operator: "StringEquals", Key: "ghost", Values: []string{"x"}}
	r, err := EvalCondition(c, ctxWith(map[string]Value{}))
	if r != CondError || err.Reason != CondErrMissingKey {
		t.Fatalf("want MissingKey, got %v %v", r, err)
	}
}

func TestUnknownOperatorDistinguishable(t *testing.T) {
	c := Condition{Operator: "Bogus", Key: "k", Values: []string{"x"}}
	r, err := EvalCondition(c, ctxWith(map[string]Value{"k": {Type: TypeString, Str: "x"}}))
	if r != CondError || err.Reason != CondErrUnknownOperator {
		t.Fatalf("want UnknownOperator, got %v %v", r, err)
	}
}
