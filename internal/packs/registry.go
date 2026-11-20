// Package packs resolves named policy packs into a deterministic list of
// policies, loading each source through its engine adapter.
package packs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cosmosdevops/kube-policy-mcp/internal/config"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// PackInfo is a short description of a configured pack.
type PackInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Extends     []string        `json:"extends,omitempty"`
	Sources     []config.Source `json:"sources,omitempty"`
	Default     bool            `json:"default,omitempty"`
	// Problem is set when the pack cannot be used, for example because it
	// needs an engine that is not available.
	Problem string `json:"problem,omitempty"`
}

// Exemption is a pack-level exemption together with the pack that defined it.
type Exemption struct {
	config.Exemption
	Pack string
}

// Resolved is a fully resolved pack.
type Resolved struct {
	Name        string
	Description string
	// Chain is the resolution order: ancestors first, the pack itself last.
	Chain []string
	// Policies are sorted by ID.
	Policies   []policy.Policy
	Exemptions []Exemption
	// Notes records overrides and loader warnings.
	Notes []string
}

// Registry discovers and caches policies for the configured packs.
type Registry struct {
	cfg     *config.Config
	engines map[string]policy.Engine
	// unavailable explains why a known engine cannot be used.
	unavailable map[string]string

	mu    sync.Mutex
	cache map[string]cachedSource
}

type cachedSource struct {
	fingerprint string
	result      policy.LoadResult
}

// NewRegistry creates a registry over the given config and engines.
func NewRegistry(cfg *config.Config, engines ...policy.Engine) *Registry {
	r := &Registry{cfg: cfg, engines: map[string]policy.Engine{}, unavailable: map[string]string{}, cache: map[string]cachedSource{}}
	for _, e := range engines {
		r.engines[e.Name()] = e
	}
	return r
}

// SetUnavailable records why an engine cannot be used, for error messages.
func (r *Registry) SetUnavailable(name, reason string) { r.unavailable[name] = reason }

// engineProblem explains why a source's engine cannot be used. A pack that
// needs such an engine is refused as a whole: dropping its policies quietly
// would make a resource look more compliant than it is.
func (r *Registry) engineProblem(name string) string {
	if _, ok := r.engines[name]; ok {
		return ""
	}
	reason, ok := r.unavailable[name]
	if !ok {
		reason = "is not part of this build"
	}
	return fmt.Sprintf("engine %q, which %s (available: %s)", name, reason, strings.Join(r.EngineNames(), ", "))
}

// Engine returns the adapter registered under name.
func (r *Registry) Engine(name string) (policy.Engine, bool) {
	e, ok := r.engines[name]
	return e, ok
}

// EngineNames lists registered engines in sorted order.
func (r *Registry) EngineNames() []string {
	var out []string
	for n := range r.engines {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DefaultPack returns the pack to use when a request names none: the
// configured default, or the only pack when exactly one exists.
func (r *Registry) DefaultPack() string {
	if r.cfg.DefaultPolicyPack != "" {
		return r.cfg.DefaultPolicyPack
	}
	if len(r.cfg.PolicyPacks) == 1 {
		return r.cfg.PolicyPacks[0].Name
	}
	return ""
}

// Packs lists the configured packs in config order.
func (r *Registry) Packs() []PackInfo {
	def := r.DefaultPack()
	out := make([]PackInfo, 0, len(r.cfg.PolicyPacks))
	for _, p := range r.cfg.PolicyPacks {
		info := PackInfo{Name: p.Name, Description: p.Description, Extends: p.Extends, Sources: p.Sources, Default: p.Name == def}
		if chain, err := r.linearize(p.Name); err != nil {
			info.Problem = err.Error()
		} else {
		search:
			for _, member := range chain {
				for _, src := range member.Sources {
					if problem := r.engineProblem(src.Engine); problem != "" {
						info.Problem = fmt.Sprintf("pack %q needs %s", member.Name, problem)
						break search
					}
				}
			}
		}
		out = append(out, info)
	}
	return out
}

func (r *Registry) pack(name string) (*config.Pack, bool) {
	for i := range r.cfg.PolicyPacks {
		if r.cfg.PolicyPacks[i].Name == name {
			return &r.cfg.PolicyPacks[i], true
		}
	}
	return nil, false
}

// linearize returns the pack and its ancestors, ancestors first. Each pack
// appears once, at its first position in a depth-first walk of "extends".
func (r *Registry) linearize(name string) ([]*config.Pack, error) {
	var order []*config.Pack
	done := map[string]bool{}
	onStack := map[string]bool{}
	var visit func(n string, from string) error
	visit = func(n, from string) error {
		p, ok := r.pack(n)
		if !ok {
			if from == "" {
				return fmt.Errorf("unknown policy pack %q", n)
			}
			return fmt.Errorf("policy pack %q extends unknown pack %q", from, n)
		}
		if onStack[n] {
			return fmt.Errorf("policy pack %q is part of an extends cycle", n)
		}
		if done[n] {
			return nil
		}
		onStack[n] = true
		for _, parent := range p.Extends {
			if err := visit(parent, n); err != nil {
				return err
			}
		}
		onStack[n] = false
		done[n] = true
		order = append(order, p)
		return nil
	}
	if err := visit(name, ""); err != nil {
		return nil, err
	}
	return order, nil
}

// Resolve loads every policy of a pack and its ancestors.
//
// Precedence: packs are processed ancestors first. When two sources supply a
// policy with the same ID, the one processed later wins, so a child pack
// overrides its parents and a later source overrides an earlier one.
func (r *Registry) Resolve(ctx context.Context, name string) (*Resolved, error) {
	chain, err := r.linearize(name)
	if err != nil {
		return nil, err
	}
	top := chain[len(chain)-1]
	res := &Resolved{Name: top.Name, Description: top.Description}
	byID := map[string]policy.Policy{}
	seenSource := map[string]bool{}
	for _, p := range chain {
		res.Chain = append(res.Chain, p.Name)
		for _, e := range p.Exemptions {
			res.Exemptions = append(res.Exemptions, Exemption{Exemption: e, Pack: p.Name})
		}
		for _, src := range p.Sources {
			key := src.Engine + "\x00" + src.Path
			if seenSource[key] {
				continue
			}
			seenSource[key] = true
			lr, err := r.load(ctx, src)
			if err != nil {
				return nil, fmt.Errorf("policy pack %q: %w", p.Name, err)
			}
			for _, w := range lr.Warnings {
				res.Notes = append(res.Notes, fmt.Sprintf("%s source %s: %s", src.Engine, src.Path, w))
			}
			for _, pol := range lr.Policies {
				pol.Pack = p.Name
				if old, dup := byID[pol.ID]; dup {
					res.Notes = append(res.Notes, fmt.Sprintf("policy %s from %s (pack %s) overrides the one from %s (pack %s)", pol.ID, pol.SourcePath, pol.Pack, old.SourcePath, old.Pack))
				}
				byID[pol.ID] = pol
			}
		}
	}
	for _, pol := range byID {
		res.Policies = append(res.Policies, pol)
	}
	sort.Slice(res.Policies, func(i, j int) bool { return res.Policies[i].ID < res.Policies[j].ID })
	return res, nil
}

func (r *Registry) load(ctx context.Context, src config.Source) (policy.LoadResult, error) {
	if problem := r.engineProblem(src.Engine); problem != "" {
		return policy.LoadResult{}, fmt.Errorf("source %s cannot be used: %s", src.Path, problem)
	}
	eng := r.engines[src.Engine]
	fp, err := fingerprint(src.Path)
	if err != nil {
		return policy.LoadResult{}, fmt.Errorf("policy source %s: %w", src.Path, err)
	}
	key := src.Engine + "\x00" + src.Path
	r.mu.Lock()
	c, hit := r.cache[key]
	r.mu.Unlock()
	if hit && c.fingerprint == fp {
		return c.result, nil
	}
	lim := policy.Limits{MaxPolicyBytes: r.cfg.Limits.MaxPolicyBytes, MaxPolicyFiles: r.cfg.Limits.MaxPolicyFiles}
	lr, err := eng.LoadSource(ctx, src.Path, lim)
	if err != nil {
		return policy.LoadResult{}, fmt.Errorf("loading %s policies from %s: %w", src.Engine, src.Path, err)
	}
	if err := checkIdentity(eng.Name(), lr.Policies); err != nil {
		return policy.LoadResult{}, fmt.Errorf("engine %s returned invalid policies for %s: %w", src.Engine, src.Path, err)
	}
	r.mu.Lock()
	r.cache[key] = cachedSource{fingerprint: fp, result: lr}
	r.mu.Unlock()
	return lr, nil
}

// checkIdentity enforces the rules every adapter must follow so that policy
// ids stay unique across engines: the policy names its own engine, its id
// starts with "<engine>/", and ids are unique within a source.
func checkIdentity(engine string, policies []policy.Policy) error {
	seen := map[string]bool{}
	for _, p := range policies {
		switch {
		case p.Engine != engine:
			return fmt.Errorf("policy %q claims engine %q", p.ID, p.Engine)
		case !strings.HasPrefix(p.ID, engine+"/") || len(p.ID) == len(engine)+1:
			return fmt.Errorf("policy id %q does not start with %q", p.ID, engine+"/")
		case seen[p.ID]:
			return fmt.Errorf("policy id %q is returned more than once", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

// fingerprint summarises names, sizes and modification times under a path so
// that edited policies are reloaded without restarting the server.
func fingerprint(path string) (string, error) {
	h := sha256.New()
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		fmt.Fprintf(h, "%s|%d|%d\n", path, info.Size(), info.ModTime().UnixNano())
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s|%d|%d\n", p, fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
