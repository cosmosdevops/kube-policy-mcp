// Package builtin links the engine adapters into a binary. It has no code of
// its own: each file blank-imports one adapter and can be left out with a
// build tag.
//
//	go build ./cmd/kube-policy-mcp                           all engines
//	go build -tags no_gatekeeper ./cmd/kube-policy-mcp       without Gatekeeper
//	go build -tags "no_vap no_gatekeeper" ./cmd/kube-policy-mcp   OPA only
//
// The tags are no_opa, no_vap and no_gatekeeper.
//
// To add an engine, write an adapter package that calls engines.Register
// from an init function and add one file here that imports it.
package builtin
