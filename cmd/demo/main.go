// Command demo runs a handful of authorization requests through the
// engine and prints the request, matched rules and final decision for each.
package main

import (
	"fmt"
	"time"

	"github.com/h3yow/iam-policy-engine-go/pkg/engine"
	"github.com/h3yow/iam-policy-engine-go/pkg/policy"
)

func must(id, raw string) *policy.Document {
	d, err := policy.Parse([]byte(raw))
	if err != nil {
		panic(err)
	}
	d.ID = id
	return d
}

func main() {
	identity := []*policy.Document{
		must("read-write", `{"Version":"2012-10-17","Statement":[
			{"Sid":"S3ReadWrite","Effect":"Allow","Action":"s3:*","Resource":"*"},
			{"Sid":"NoSecrets","Effect":"Deny","Action":"s3:GetObject",
			 "Resource":"arn:aws:s3:::secret/*"}]}`),
	}
	boundary := []*policy.Document{
		must("read-only-boundary", `{"Statement":[
			{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`),
	}
	session := []*policy.Document{
		must("scoped-session", `{"Statement":[
			{"Effect":"Allow","Action":"s3:GetObject",
			 "Resource":"arn:aws:s3:::shared/*",
			 "Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}}]}`),
	}

	eng := engine.New(identity, boundary, session)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	scenarios := []struct {
		name  string
		ctx   *policy.RequestContext
		creds *engine.Credentials
	}{
		{
			name: "allowed: scoped read on shared bucket from corporate IP",
			ctx: &policy.RequestContext{
				PrincipalARN: "arn:aws:iam::111111:user/alice", AccountID: "111111",
				Action: "s3:GetObject", Resource: "arn:aws:s3:::shared/report.csv",
				Keys: map[string]policy.Value{
					"aws:SourceIp": {Type: policy.TypeString, Str: "10.20.30.40"},
				},
				Now: now,
			},
			creds: &engine.Credentials{AccessKeyID: "AKIAFRESH", ExpiresAt: now.Add(time.Hour)},
		},
		{
			name: "denied: write blocked by read-only boundary",
			ctx: &policy.RequestContext{
				PrincipalARN: "arn:aws:iam::111111:user/alice", AccountID: "111111",
				Action: "s3:PutObject", Resource: "arn:aws:s3:::shared/a",
				Keys: map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeString, Str: "10.20.30.40"}},
				Now:  now,
			},
		},
		{
			name: "denied: explicit deny on secrets overrides allow",
			ctx: &policy.RequestContext{
				PrincipalARN: "arn:aws:iam::111111:user/alice", AccountID: "111111",
				Action: "s3:GetObject", Resource: "arn:aws:s3:::secret/keys",
				Keys: map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeString, Str: "10.20.30.40"}},
				Now:  now,
			},
		},
		{
			name: "denied: credentials expired",
			ctx: &policy.RequestContext{
				PrincipalARN: "arn:aws:iam::111111:user/alice", AccountID: "111111",
				Action: "s3:GetObject", Resource: "arn:aws:s3:::shared/report.csv",
				Keys: map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeString, Str: "10.20.30.40"}},
				Now:  now,
			},
			creds: &engine.Credentials{AccessKeyID: "AKIAOLD", ExpiresAt: now.Add(-time.Minute)},
		},
		{
			name: "denied: condition key has wrong type",
			ctx: &policy.RequestContext{
				PrincipalARN: "arn:aws:iam::111111:user/alice", AccountID: "111111",
				Action: "s3:GetObject", Resource: "arn:aws:s3:::shared/report.csv",
				Keys: map[string]policy.Value{"aws:SourceIp": {Type: policy.TypeNumber, Num: 10}},
				Now:  now,
			},
		},
	}

	for _, sc := range scenarios {
		ev := eng.Evaluate(sc.ctx, sc.creds)
		fmt.Printf("\n### %s\n%s\n", sc.name, engine.Explain(sc.ctx, ev))
	}
}
