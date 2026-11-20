// Package builtin links the engine adapters into a binary. It has no code of
// its own: each file blank-imports one adapter and can be left out with a
// build tag.
//
//	go build ./cmd/kube-policy-mcp                    all engines
//	go build -tags no_kyverno ./cmd/kube-policy-mcp   without Kyverno
//	go build -tags no_opa ./cmd/kube-policy-mcp       without OPA
//
// To add an engine, write an adapter package that calls engines.Register
// from an init function and add one file here that imports it.
package builtin
