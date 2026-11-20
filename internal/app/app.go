// Package app wires the configuration, engines, registry and evaluator
// together. Both the CLI and the MCP server are thin layers over it.
package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cosmosdevops/kube-policy-mcp/internal/config"
	"github.com/cosmosdevops/kube-policy-mcp/internal/engines"
	"github.com/cosmosdevops/kube-policy-mcp/internal/evaluator"
	"github.com/cosmosdevops/kube-policy-mcp/internal/manifests"
	"github.com/cosmosdevops/kube-policy-mcp/internal/packs"
	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Version is the application version, set at build time with -ldflags.
var Version = "0.1.0-dev"

// ConfigEnv names the environment variable that points at the config file.
const ConfigEnv = "KUBE_POLICY_MCP_CONFIG"

// DefaultConfigFile is looked up in the working directory.
const DefaultConfigFile = "kube-policy-mcp.yaml"

// App is the assembled application core.
type App struct {
	Config    *config.Config
	Registry  *packs.Registry
	Evaluator *evaluator.Evaluator
	Workspace *manifests.Workspace
	// Engines describes every engine linked into this binary, including
	// those the configuration turns off.
	Engines []engines.Info
}

// ResolveConfigPath picks the config file: the flag, then the environment
// variable, then ./kube-policy-mcp.yaml.
func ResolveConfigPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv(ConfigEnv); env != "" {
		return env, nil
	}
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		return DefaultConfigFile, nil
	}
	return "", fmt.Errorf("no configuration found: pass --config, set %s, or create ./%s", ConfigEnv, DefaultConfigFile)
}

// New loads the config and builds the application. extraRoots are added to
// the configured workspace roots.
func New(configPath string, extraRoots []string) (*App, error) {
	path, err := ResolveConfigPath(configPath)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	ws, err := manifests.NewWorkspace(append(append([]string(nil), cfg.WorkspaceRoots...), extraRoots...))
	if err != nil {
		return nil, err
	}
	timeout, err := cfg.Timeout()
	if err != nil {
		return nil, err
	}
	active, infos, err := buildEngines(cfg)
	if err != nil {
		return nil, err
	}
	reg := packs.NewRegistry(cfg, active...)
	for _, info := range infos {
		if !info.Enabled {
			reg.SetUnavailable(info.Name, "is turned off in the configuration (engines."+info.Name+".enabled: false)")
		}
	}
	return &App{
		Config:    cfg,
		Registry:  reg,
		Evaluator: &evaluator.Evaluator{Registry: reg, Timeout: timeout},
		Workspace: ws,
		Engines:   infos,
	}, nil
}

// buildEngines creates the adapters that are linked in and not turned off.
// Which engines exist is decided by what the binary links (see the
// engines/builtin package); this function never names one.
func buildEngines(cfg *config.Config) (active []policy.Engine, infos []engines.Info, err error) {
	regs := engines.Registered()
	if len(regs) == 0 {
		return nil, nil, fmt.Errorf("this binary was built without any policy engine")
	}
	for name, ec := range cfg.Engines {
		// Turning off an engine that is absent is harmless. Asking for one
		// that is absent is a mistake worth stopping for.
		if !engines.IsRegistered(name) && (ec.Enabled == nil || *ec.Enabled) {
			return nil, nil, fmt.Errorf("the configuration mentions engine %q, which is not part of this build (available: %s)", name, strings.Join(engines.Names(), ", "))
		}
	}
	for _, r := range regs {
		eng := r.New()
		if eng.Name() != r.Name {
			return nil, nil, fmt.Errorf("engine registered as %q calls itself %q", r.Name, eng.Name())
		}
		enabled := cfg.EngineEnabled(r.Name)
		infos = append(infos, r.Describe(eng, enabled))
		if enabled {
			active = append(active, eng)
		}
	}
	if len(active) == 0 {
		return nil, nil, fmt.Errorf("every policy engine is turned off in the configuration")
	}
	return active, infos, nil
}

// ManifestLimits returns the configured manifest input limits.
func (a *App) ManifestLimits() manifests.Limits {
	return manifests.Limits{MaxBytes: a.Config.Limits.MaxManifestBytes, MaxResources: a.Config.Limits.MaxResources}
}

// DirLimits returns the configured directory walk limits.
func (a *App) DirLimits() manifests.DirLimits {
	return manifests.DirLimits{Limits: a.ManifestLimits(), MaxFiles: a.Config.Limits.MaxFiles}
}

// PackName returns name, or the default pack when name is empty.
func (a *App) PackName(name string) (string, error) {
	if name != "" {
		return name, nil
	}
	if def := a.Registry.DefaultPack(); def != "" {
		return def, nil
	}
	var names []string
	for _, p := range a.Registry.Packs() {
		names = append(names, p.Name)
	}
	return "", fmt.Errorf("no policy pack given and no default is configured; available packs: %s", strings.Join(names, ", "))
}

// PolicyFilter narrows a policy listing. Empty fields match everything.
type PolicyFilter struct {
	Pack      string
	Engine    string
	Kind      string
	Severity  string
	Namespace string
}

// PolicyList is the result of listing policies.
type PolicyList struct {
	Pack     string
	Chain    []string
	Policies []policy.Policy
	Notes    []string
}

// ListPolicies returns the policies of a pack that match the filter.
func (a *App) ListPolicies(ctx context.Context, f PolicyFilter) (*PolicyList, error) {
	name, err := a.PackName(f.Pack)
	if err != nil {
		return nil, err
	}
	res, err := a.Registry.Resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	out := &PolicyList{Pack: res.Name, Chain: res.Chain, Notes: res.Notes}
	for _, p := range res.Policies {
		if f.Engine != "" && !strings.EqualFold(p.Engine, f.Engine) {
			continue
		}
		if f.Severity != "" && !strings.EqualFold(p.Severity, f.Severity) {
			continue
		}
		if f.Kind != "" && !p.AppliesToKind(f.Kind) {
			continue
		}
		if f.Namespace != "" {
			// A namespaced policy only applies inside its own namespace.
			if m, ok := p.Match.(map[string]any); ok {
				if ns, ok := m["namespace"].(string); ok && ns != f.Namespace {
					continue
				}
			}
		}
		out.Policies = append(out.Policies, p)
	}
	return out, nil
}

// GetPolicy finds one policy of a pack by id, or by name when unique.
func (a *App) GetPolicy(ctx context.Context, pack, id string) (*policy.Policy, error) {
	name, err := a.PackName(pack)
	if err != nil {
		return nil, err
	}
	res, err := a.Registry.Resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	var hits []policy.Policy
	for _, p := range res.Policies {
		if p.ID == id || p.Name == id {
			hits = append(hits, p)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("policy %q is not in pack %q; use list_policies to see valid ids", id, name)
	case 1:
		return &hits[0], nil
	}
	return nil, fmt.Errorf("policy name %q is ambiguous in pack %q; use the full id", id, name)
}
