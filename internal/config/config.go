// Package config loads the server configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"
)

// Source is one policy source for one engine. What the path must contain is
// defined by the engine.
type Source struct {
	Engine string `json:"engine"`
	Path   string `json:"path"`
}

// ResourceSelector selects resources for an exemption. Empty fields match
// anything. Names and namespaces accept "*" wildcards.
type ResourceSelector struct {
	Kinds      []string `json:"kinds,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Names      []string `json:"names,omitempty"`
}

// Exemption waives policies for selected resources at the pack level. It is
// the exception mechanism for engines without a native one.
type Exemption struct {
	Name     string           `json:"name"`
	Policies []string         `json:"policies"`
	Resource ResourceSelector `json:"resources"`
	Reason   string           `json:"reason"`
	// Expires is an optional date (YYYY-MM-DD). After it the exemption is ignored.
	Expires string `json:"expires,omitempty"`
}

// Pack is a named set of policy sources.
type Pack struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Extends     []string    `json:"extends,omitempty"`
	Sources     []Source    `json:"sources,omitempty"`
	Exemptions  []Exemption `json:"exemptions,omitempty"`
}

// Limits bounds input sizes and evaluation time.
type Limits struct {
	MaxManifestBytes  int64  `json:"maxManifestBytes,omitempty"`
	MaxResources      int    `json:"maxResources,omitempty"`
	MaxFiles          int    `json:"maxFiles,omitempty"`
	MaxPolicyBytes    int64  `json:"maxPolicyBytes,omitempty"`
	MaxPolicyFiles    int    `json:"maxPolicyFiles,omitempty"`
	EvaluationTimeout string `json:"evaluationTimeout,omitempty"`
}

// Engine holds per-engine configuration.
type Engine struct {
	// Enabled turns an engine off when false. Engines are on by default.
	Enabled *bool `json:"enabled,omitempty"`
}

// Config is the content of kube-policy-mcp.yaml.
type Config struct {
	// WorkspaceRoots are the only directories manifests may be read from.
	WorkspaceRoots []string `json:"workspaceRoots,omitempty"`
	// DefaultPolicyPack is used when a request names no pack.
	DefaultPolicyPack string `json:"defaultPolicyPack,omitempty"`
	Limits            Limits `json:"limits,omitempty"`
	// Engines optionally configures engines by name. An engine that is not
	// mentioned is enabled.
	Engines     map[string]Engine `json:"engines,omitempty"`
	PolicyPacks []Pack            `json:"policyPacks"`

	// Dir is the directory of the config file; relative paths resolve from it.
	Dir string `json:"-"`
}

// Defaults for limits.
const (
	DefaultMaxManifestBytes = 5 << 20
	DefaultMaxResources     = 500
	DefaultMaxFiles         = 2000
	DefaultMaxPolicyBytes   = 2 << 20
	DefaultMaxPolicyFiles   = 2000
	DefaultTimeout          = 30 * time.Second
)

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var c Config
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.Dir = filepath.Dir(abs)
	if err := c.finish(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) finish() error {
	l := &c.Limits
	if l.MaxManifestBytes <= 0 {
		l.MaxManifestBytes = DefaultMaxManifestBytes
	}
	if l.MaxResources <= 0 {
		l.MaxResources = DefaultMaxResources
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}
	if l.MaxPolicyBytes <= 0 {
		l.MaxPolicyBytes = DefaultMaxPolicyBytes
	}
	if l.MaxPolicyFiles <= 0 {
		l.MaxPolicyFiles = DefaultMaxPolicyFiles
	}
	if _, err := c.Timeout(); err != nil {
		return err
	}
	for i, r := range c.WorkspaceRoots {
		c.WorkspaceRoots[i] = c.abs(r)
	}
	seen := map[string]bool{}
	for pi := range c.PolicyPacks {
		p := &c.PolicyPacks[pi]
		if p.Name == "" {
			return fmt.Errorf("policyPacks[%d] has no name", pi)
		}
		if seen[p.Name] {
			return fmt.Errorf("policy pack %q is defined twice", p.Name)
		}
		seen[p.Name] = true
		for si := range p.Sources {
			s := &p.Sources[si]
			if s.Engine == "" || s.Path == "" {
				return fmt.Errorf("policy pack %q: sources[%d] needs engine and path", p.Name, si)
			}
			s.Path = c.abs(s.Path)
		}
		for ei, e := range p.Exemptions {
			if e.Name == "" || len(e.Policies) == 0 || e.Reason == "" {
				return fmt.Errorf("policy pack %q: exemptions[%d] needs name, policies and reason", p.Name, ei)
			}
			if e.Expires != "" {
				if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
					return fmt.Errorf("policy pack %q: exemption %q: expires must be YYYY-MM-DD", p.Name, e.Name)
				}
			}
		}
	}
	if c.DefaultPolicyPack != "" && !seen[c.DefaultPolicyPack] {
		return fmt.Errorf("defaultPolicyPack %q is not a defined pack", c.DefaultPolicyPack)
	}
	return nil
}

func (c *Config) abs(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(c.Dir, p)
}

// EngineEnabled reports whether the configuration leaves an engine on.
func (c *Config) EngineEnabled(name string) bool {
	e, ok := c.Engines[name]
	return !ok || e.Enabled == nil || *e.Enabled
}

// Timeout returns the evaluation timeout.
func (c *Config) Timeout() (time.Duration, error) {
	if c.Limits.EvaluationTimeout == "" {
		return DefaultTimeout, nil
	}
	d, err := time.ParseDuration(c.Limits.EvaluationTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("limits.evaluationTimeout %q is not a valid positive duration", c.Limits.EvaluationTimeout)
	}
	return d, nil
}
