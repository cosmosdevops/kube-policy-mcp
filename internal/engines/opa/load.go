// Package opa is the OPA/Rego policy engine adapter. It embeds the upstream
// OPA libraries and follows Conftest conventions: a policy is a Rego package
// with deny, violation or warn rules, and the Kubernetes resource is input.
package opa

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"sigs.k8s.io/yaml"

	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// ReservedRoot is the data key under which the adapter exposes the
// evaluation context to Rego (data.kubepolicy).
const ReservedRoot = "kubepolicy"

// Rule names with a meaning to the adapter.
const (
	ruleDeny      = "deny"
	ruleViolation = "violation"
	ruleWarn      = "warn"
	ruleUnknown   = "unknown"
	ruleApplies   = "applies"
)

var resultRules = []string{ruleDeny, ruleViolation, ruleWarn, ruleUnknown}

// deniedBuiltins can reach the network or the host environment, so policies
// that use them fail to compile.
var deniedBuiltins = []string{"http.send", "net.lookup_ip_addr", "opa.runtime"}

// unit is one compiled policy source. All packages of a source are compiled
// together so that policies can import helper packages from the same source.
type unit struct {
	path       string
	compiler   *ast.Compiler
	compileErr error
	data       map[string]any
}

// native is the engine-private state attached to each policy.
type native struct {
	unit  *unit
	pkg   string // "data.kubernetes.host_network"
	rules map[string]bool
}

type sourceFile struct {
	rel string
	raw []byte
}

// Engine is the OPA adapter.
type Engine struct{}

// New returns the OPA adapter.
func New() *Engine { return &Engine{} }

// Name implements policy.Engine.
func (*Engine) Name() string { return EngineName }

// SupportedPolicyTypes implements policy.Engine.
func (*Engine) SupportedPolicyTypes() []string { return []string{"rego"} }

func capabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	caps.Builtins = slices.DeleteFunc(caps.Builtins, func(b *ast.Builtin) bool {
		return slices.Contains(deniedBuiltins, b.Name)
	})
	caps.AllowNet = []string{}
	return caps
}

// LoadSource implements policy.Engine. path is a directory of .rego files
// (optionally laid out as an OPA bundle with data.json or data.yaml files) or
// a bundle tarball (.tar.gz).
func (e *Engine) LoadSource(ctx context.Context, path string, lim policy.Limits) (policy.LoadResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return policy.LoadResult{}, err
	}
	var regoFiles, dataFiles []sourceFile
	if info.IsDir() {
		regoFiles, dataFiles, err = readDir(path, lim)
	} else if strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz") {
		regoFiles, dataFiles, err = readTarball(path, lim)
	} else {
		err = fmt.Errorf("%s is neither a directory nor a .tar.gz bundle", path)
	}
	if err != nil {
		return policy.LoadResult{}, err
	}

	var res policy.LoadResult
	u := &unit{path: path, data: map[string]any{}}

	for _, f := range dataFiles {
		var doc any
		if err := yaml.Unmarshal(f.raw, &doc); err != nil {
			return res, fmt.Errorf("data file %s: %w", f.rel, err)
		}
		if err := mount(u.data, filepath.Dir(f.rel), doc); err != nil {
			return res, fmt.Errorf("data file %s: %w", f.rel, err)
		}
	}
	if _, clash := u.data[ReservedRoot]; clash {
		return res, fmt.Errorf("data root %q is reserved for the evaluation context", ReservedRoot)
	}

	modules := map[string]*ast.Module{}
	raws := map[string]string{}
	for _, f := range regoFiles {
		mod, err := parse(f.rel, string(f.raw))
		if err != nil {
			// A file that does not parse becomes a broken policy so that
			// evaluation reports an error instead of silently skipping it.
			res.Policies = append(res.Policies, policy.Policy{
				ID: EngineName + "/" + f.rel, Name: f.rel, Engine: EngineName, Type: "rego",
				SourcePath: filepath.Join(path, f.rel), Problem: "failed to parse: " + err.Error(), LoadError: true,
				Raw: string(f.raw), Native: &native{unit: u},
			})
			continue
		}
		modules[f.rel] = mod
		raws[f.rel] = string(f.raw)
	}

	c := ast.NewCompiler().WithCapabilities(capabilities()).WithEnablePrintStatements(false)
	c.Compile(modules)
	if c.Failed() {
		u.compileErr = fmt.Errorf("rego compilation failed: %w", c.Errors)
	} else {
		u.compiler = c
	}

	annots, _ := ast.BuildAnnotationSet(sortedModules(modules))
	var flat ast.FlatAnnotationsRefSet
	if annots != nil {
		flat = annots.Flatten()
	}

	byPkg := map[string][]string{}
	for name, mod := range modules {
		byPkg[mod.Package.Path.String()] = append(byPkg[mod.Package.Path.String()], name)
	}
	for pkg, files := range byPkg {
		sort.Strings(files)
		rules := map[string]bool{}
		for _, f := range files {
			for _, r := range modules[f].Rules {
				rules[r.Head.Name.String()] = true
				if len(r.Head.Ref()) > 0 {
					rules[strings.Trim(r.Head.Ref()[0].Value.String(), `"`)] = true
				}
			}
		}
		isPolicy := false
		for _, rn := range resultRules {
			isPolicy = isPolicy || rules[rn]
		}
		if !isPolicy {
			continue // helper library package
		}
		name := strings.TrimPrefix(pkg, "data.")
		p := policy.Policy{
			ID: EngineName + "/" + name, Name: name, Engine: EngineName, Type: "rego",
			SourcePath: filepath.Join(path, files[0]), Supported: true,
			Native: &native{unit: u, pkg: pkg, rules: rules},
		}
		var raw []string
		for _, f := range files {
			raw = append(raw, "# file: "+f+"\n"+raws[f])
		}
		p.Raw = strings.Join(raw, "\n")
		applyAnnotations(&p, pkg, rules, flat)
		if rules[ruleDeny] || rules[ruleViolation] {
			p.Enforcement = policy.EnforceDeny
		} else if rules[ruleWarn] {
			p.Enforcement = policy.EnforceWarn
		}
		if u.compileErr != nil {
			p.Problem, p.LoadError = u.compileErr.Error(), true
		}
		res.Policies = append(res.Policies, p)
	}
	sort.Slice(res.Policies, func(i, j int) bool { return res.Policies[i].ID < res.Policies[j].ID })
	return res, nil
}

// ValidatePolicy implements policy.Engine.
func (*Engine) ValidatePolicy(_ context.Context, p policy.Policy) error {
	if p.LoadError {
		return errors.New(p.Problem)
	}
	n, ok := p.Native.(*native)
	if !ok || n.unit == nil {
		return errors.New("policy was not loaded by the opa engine")
	}
	return n.unit.compileErr
}

// parse tries Rego v1 syntax first and falls back to v0 for older policies.
func parse(name, src string) (*ast.Module, error) {
	mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV1})
	if err == nil {
		if mod == nil {
			return nil, errors.New("empty module")
		}
		return mod, nil
	}
	if old, err0 := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{ProcessAnnotation: true, RegoVersion: ast.RegoV0}); err0 == nil && old != nil {
		return old, nil
	}
	return nil, err
}

func sortedModules(m map[string]*ast.Module) []*ast.Module {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*ast.Module, 0, len(m))
	for _, n := range names {
		out = append(out, m[n])
	}
	return out
}

// applyAnnotations copies OPA metadata annotations into the policy.
func applyAnnotations(p *policy.Policy, pkg string, rules map[string]bool, flat ast.FlatAnnotationsRefSet) {
	ruleDocs := map[string][]string{}
	for _, ref := range flat {
		a := ref.Annotations
		if a == nil {
			continue
		}
		path := ref.Path.String()
		switch {
		case (a.Scope == "package" || a.Scope == "subpackages") && path == pkg:
			if a.Title != "" {
				p.Title = a.Title
			}
			if a.Description != "" {
				p.Description = a.Description
			}
			for _, rr := range a.RelatedResources {
				p.Docs = append(p.Docs, rr.Ref.String())
			}
			custom(p, a.Custom)
		case (a.Scope == "rule" || a.Scope == "document") && strings.HasPrefix(path, pkg+"."):
			name := strings.TrimPrefix(path, pkg+".")
			text := a.Title
			if a.Description != "" {
				text = strings.TrimSpace(text + ": " + a.Description)
				text = strings.TrimPrefix(text, ": ")
			}
			if text != "" && !slices.Contains(ruleDocs[name], text) {
				ruleDocs[name] = append(ruleDocs[name], text)
			}
		}
	}
	for _, rn := range resultRules {
		if !rules[rn] {
			continue
		}
		r := policy.Rule{ID: rn, Description: strings.Join(ruleDocs[rn], "; ")}
		switch rn {
		case ruleDeny, ruleViolation:
			r.Enforcement = policy.EnforceDeny
		case ruleWarn:
			r.Enforcement = policy.EnforceWarn
		case ruleUnknown:
			if r.Description == "" {
				r.Description = "reports when compliance cannot be determined from the supplied context"
			}
		}
		p.Rules = append(p.Rules, r)
	}
}

func custom(p *policy.Policy, c map[string]any) {
	if s, ok := c["severity"].(string); ok {
		p.Severity = s
	}
	if s, ok := c["category"].(string); ok {
		p.Category = s
	}
	if s, ok := c["remediation"].(string); ok {
		p.Remediation = strings.TrimSpace(s)
	}
	if v, ok := c["version"]; ok {
		p.Version = fmt.Sprint(v)
	}
	p.Kinds = append(p.Kinds, stringList(c["kinds"])...)
	p.RequiredContext = append(p.RequiredContext, stringList(c["requiredContext"])...)
	p.Docs = append(p.Docs, stringList(c["docs"])...)
}

func stringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// mount places a data document at the path given by its directory, following
// the OPA bundle convention (teams/data.json is loaded under data.teams).
func mount(root map[string]any, dir string, doc any) error {
	cur := root
	if dir != "." && dir != "" {
		for _, part := range strings.Split(filepath.ToSlash(dir), "/") {
			next, ok := cur[part].(map[string]any)
			if !ok {
				if _, exists := cur[part]; exists {
					return fmt.Errorf("data path conflict at %q", part)
				}
				next = map[string]any{}
				cur[part] = next
			}
			cur = next
		}
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return errors.New("top level of a data file must be an object")
	}
	return merge(cur, m)
}

func merge(dst, src map[string]any) error {
	for k, v := range src {
		if old, ok := dst[k]; ok {
			om, ok1 := old.(map[string]any)
			nm, ok2 := v.(map[string]any)
			if ok1 && ok2 {
				if err := merge(om, nm); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("data key %q is defined more than once", k)
		}
		dst[k] = v
	}
	return nil
}

func readDir(root string, lim policy.Limits) (regoFiles, dataFiles []sourceFile, err error) {
	count := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		isRego := strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego")
		isData := name == "data.json" || name == "data.yaml" || name == "data.yml"
		if !isRego && !isData {
			return nil
		}
		count++
		if lim.MaxPolicyFiles > 0 && count > lim.MaxPolicyFiles {
			return fmt.Errorf("more than %d policy files", lim.MaxPolicyFiles)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if lim.MaxPolicyBytes > 0 && fi.Size() > lim.MaxPolicyBytes {
			return fmt.Errorf("%s is larger than the %d byte policy limit", p, lim.MaxPolicyBytes)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if isRego {
			regoFiles = append(regoFiles, sourceFile{rel, raw})
		} else {
			dataFiles = append(dataFiles, sourceFile{rel, raw})
		}
		return nil
	})
	return regoFiles, dataFiles, err
}

// readTarball reads an OPA bundle tarball without evaluating anything in it.
func readTarball(path string, lim policy.Limits) (regoFiles, dataFiles []sourceFile, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not a gzip bundle: %w", path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading bundle %s: %w", path, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+hdr.Name)), "/")
		base := filepath.Base(rel)
		isRego := strings.HasSuffix(base, ".rego") && !strings.HasSuffix(base, "_test.rego")
		isData := base == "data.json" || base == "data.yaml" || base == "data.yml"
		if !isRego && !isData {
			continue
		}
		count++
		if lim.MaxPolicyFiles > 0 && count > lim.MaxPolicyFiles {
			return nil, nil, fmt.Errorf("more than %d policy files in bundle", lim.MaxPolicyFiles)
		}
		var r io.Reader = tr
		if lim.MaxPolicyBytes > 0 {
			if hdr.Size > lim.MaxPolicyBytes {
				return nil, nil, fmt.Errorf("%s in bundle is larger than the %d byte policy limit", rel, lim.MaxPolicyBytes)
			}
			r = io.LimitReader(tr, lim.MaxPolicyBytes+1)
		}
		raw, err := io.ReadAll(r)
		if err != nil {
			return nil, nil, err
		}
		if isRego {
			regoFiles = append(regoFiles, sourceFile{rel, raw})
		} else {
			dataFiles = append(dataFiles, sourceFile{rel, raw})
		}
	}
	return regoFiles, dataFiles, nil
}
