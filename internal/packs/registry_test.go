package packs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cosmosdevops/kube-policy-mcp/internal/config"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evalctx"
	"github.com/cosmosdevops/kube-policy-mcp/internal/findings"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// fakeEngine treats every *.pol file in a source as one policy named after the file.
type fakeEngine struct{ loads int }

func (*fakeEngine) Name() string                   { return "fake" }
func (*fakeEngine) SupportedPolicyTypes() []string { return []string{"fake"} }
func (f *fakeEngine) LoadSource(_ context.Context, path string, _ policy.Limits) (policy.LoadResult, error) {
	f.loads++
	entries, err := os.ReadDir(path)
	if err != nil {
		return policy.LoadResult{}, err
	}
	var res policy.LoadResult
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pol") {
			name := strings.TrimSuffix(e.Name(), ".pol")
			res.Policies = append(res.Policies, policy.Policy{ID: "fake/" + name, Name: name, Engine: "fake", SourcePath: filepath.Join(path, e.Name()), Supported: true})
		}
	}
	return res, nil
}
func (*fakeEngine) ValidatePolicy(context.Context, policy.Policy) error { return nil }
func (*fakeEngine) Evaluate(context.Context, []manifests.Resource, []policy.Policy, evalctx.Context) ([]findings.Finding, error) {
	return nil, nil
}

func write(t *testing.T, dir string, names ...string) string {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n+".pol"), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestResolveExtendsPrecedenceAndDeterminism(t *testing.T) {
	root := t.TempDir()
	base := write(t, filepath.Join(root, "base"), "a", "b")
	sec := write(t, filepath.Join(root, "sec"), "c")
	prod := write(t, filepath.Join(root, "prod"), "b", "d")
	cfg := &config.Config{PolicyPacks: []config.Pack{
		{Name: "base", Sources: []config.Source{{Engine: "fake", Path: base}}, Exemptions: []config.Exemption{{Name: "e1", Policies: []string{"fake/a"}, Reason: "r"}}},
		{Name: "sec", Extends: []string{"base"}, Sources: []config.Source{{Engine: "fake", Path: sec}}},
		{Name: "prod", Extends: []string{"sec", "base"}, Sources: []config.Source{{Engine: "fake", Path: prod}, {Engine: "fake", Path: base}}},
	}}
	eng := &fakeEngine{}
	reg := NewRegistry(cfg, eng)
	var first *Resolved
	for i := 0; i < 5; i++ {
		res, err := reg.Resolve(context.Background(), "prod")
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = res
		} else if !reflect.DeepEqual(first, res) {
			t.Fatal("resolution is not deterministic")
		}
	}
	if got := strings.Join(first.Chain, ","); got != "base,sec,prod" {
		t.Errorf("chain = %s", got)
	}
	var ids []string
	owner := map[string]string{}
	for _, p := range first.Policies {
		ids = append(ids, p.ID)
		owner[p.ID] = p.Pack
	}
	if got := strings.Join(ids, ","); got != "fake/a,fake/b,fake/c,fake/d" {
		t.Errorf("policies = %s", got)
	}
	// The child pack's copy of "b" overrides the parent's.
	if owner["fake/b"] != "prod" || owner["fake/a"] != "base" {
		t.Errorf("owners = %v", owner)
	}
	if len(first.Notes) != 1 || !strings.Contains(first.Notes[0], "overrides") {
		t.Errorf("override not noted: %v", first.Notes)
	}
	if len(first.Exemptions) != 1 || first.Exemptions[0].Pack != "base" {
		t.Errorf("exemptions not inherited: %+v", first.Exemptions)
	}
	// Three distinct sources, loaded once each thanks to the cache.
	if eng.loads != 3 {
		t.Errorf("sources loaded %d times, want 3", eng.loads)
	}
	// Editing a source invalidates only that source.
	write(t, prod, "e")
	res, _ := reg.Resolve(context.Background(), "prod")
	if len(res.Policies) != 5 || eng.loads != 4 {
		t.Errorf("after edit: %d policies, %d loads", len(res.Policies), eng.loads)
	}
}

func TestResolveErrors(t *testing.T) {
	root := t.TempDir()
	dir := write(t, filepath.Join(root, "p"), "a")
	cfg := &config.Config{PolicyPacks: []config.Pack{
		{Name: "a", Extends: []string{"b"}},
		{Name: "b", Extends: []string{"a"}},
		{Name: "dangling", Extends: []string{"nope"}},
		{Name: "badengine", Sources: []config.Source{{Engine: "missing", Path: dir}}},
		{Name: "badpath", Sources: []config.Source{{Engine: "fake", Path: filepath.Join(root, "absent")}}},
	}}
	reg := NewRegistry(cfg, &fakeEngine{})
	for pack, want := range map[string]string{"a": "cycle", "dangling": "unknown pack", "nope": "unknown policy pack", "badengine": "not part of this build", "badpath": "no such file"} {
		_, err := reg.Resolve(context.Background(), pack)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", pack, want, err)
		}
	}
}

func TestUnavailableEnginesBlockThePackAndAreExplained(t *testing.T) {
	root := t.TempDir()
	dir := write(t, filepath.Join(root, "p"), "a")
	cfg := &config.Config{PolicyPacks: []config.Pack{
		{Name: "ok", Sources: []config.Source{{Engine: "fake", Path: dir}}},
		{Name: "needs-off", Sources: []config.Source{{Engine: "fake", Path: dir}, {Engine: "off", Path: dir}}},
		{Name: "child", Extends: []string{"needs-off"}},
		{Name: "needs-absent", Sources: []config.Source{{Engine: "absent", Path: dir}}},
	}}
	reg := NewRegistry(cfg, &fakeEngine{})
	reg.SetUnavailable("off", "is turned off in the configuration")
	problems := map[string]string{}
	for _, p := range reg.Packs() {
		problems[p.Name] = p.Problem
	}
	if problems["ok"] != "" {
		t.Errorf("usable pack flagged: %s", problems["ok"])
	}
	for pack, want := range map[string]string{"needs-off": "turned off", "child": "turned off", "needs-absent": "not part of this build"} {
		if !strings.Contains(problems[pack], want) {
			t.Errorf("%s: problem = %q, want it to mention %q", pack, problems[pack], want)
		}
		// The pack is refused as a whole; its other policies are not evaluated alone.
		if _, err := reg.Resolve(context.Background(), pack); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: resolve error = %v", pack, err)
		}
	}
}

// badIdentity returns policies that break the identity rules.
type badIdentity struct {
	fakeEngine
	policies []policy.Policy
}

func (b *badIdentity) LoadSource(context.Context, string, policy.Limits) (policy.LoadResult, error) {
	return policy.LoadResult{Policies: b.policies}, nil
}

func TestAdaptersMustKeepPolicyIdentityRules(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{PolicyPacks: []config.Pack{{Name: "p", Sources: []config.Source{{Engine: "fake", Path: dir}}}}}
	cases := map[string][]policy.Policy{
		"claims engine":   {{ID: "fake/a", Engine: "other"}},
		"does not start":  {{ID: "other/a", Engine: "fake"}},
		"more than once":  {{ID: "fake/a", Engine: "fake"}, {ID: "fake/a", Engine: "fake"}},
		`does not start `: {{ID: "fake/", Engine: "fake"}},
	}
	for want, pols := range cases {
		_, err := NewRegistry(cfg, &badIdentity{policies: pols}).Resolve(context.Background(), "p")
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}
