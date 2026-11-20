// Package engines is the plug-in point for policy engines.
//
// An engine adapter lives in its own package and registers itself from an
// init function, the way database/sql drivers do. Nothing in the core imports
// an adapter: the set of engines in a binary is decided only by which adapter
// packages are linked in (see the builtin package and its build tags).
package engines

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"sort"
	"sync"

	"github.com/cosmosdevops/kube-policy-mcp/internal/policy"
)

// Registration describes an engine adapter. Everything the rest of the
// program says about an engine (tool descriptions, listings, documentation
// output) comes from here, so the core never names an engine itself.
type Registration struct {
	// Name is the identifier used in the config file ("engine: opa") and as
	// the prefix of policy ids. Lower-case letters, digits and dashes.
	Name string
	// Title is the display name, for example "OPA / Rego".
	Title string
	// Description says in one sentence what the adapter evaluates.
	Description string
	// SourceFormat says what a policy source path must contain.
	SourceFormat string
	// NativeExceptions says how the engine expresses exceptions, if it can.
	NativeExceptions string
	// Limitations lists what the adapter cannot do offline.
	Limitations []string
	// Module is the Go module path of the upstream engine. It is used to
	// report the embedded version.
	Module string
	// New creates the adapter.
	New func() policy.Engine
}

// Info is the public description of an engine in a running program.
type Info struct {
	Name             string   `json:"name"`
	Title            string   `json:"title"`
	Description      string   `json:"description,omitempty"`
	PolicyTypes      []string `json:"policyTypes"`
	SourceFormat     string   `json:"sourceFormat,omitempty"`
	NativeExceptions string   `json:"nativeExceptions,omitempty"`
	Limitations      []string `json:"limitations,omitempty"`
	// UpstreamVersion is the version of the embedded upstream engine.
	UpstreamVersion string `json:"upstreamVersion,omitempty"`
	// Enabled is false when the configuration turns the engine off.
	Enabled bool `json:"enabled"`
}

var (
	mu            sync.RWMutex
	registrations = map[string]Registration{}
	validName     = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Register adds an engine adapter. It panics on an invalid or duplicate
// registration, because that is a programming error found at start-up.
func Register(r Registration) {
	mu.Lock()
	defer mu.Unlock()
	if !validName.MatchString(r.Name) {
		panic(fmt.Sprintf("engines: invalid engine name %q", r.Name))
	}
	if r.New == nil {
		panic(fmt.Sprintf("engines: engine %q has no constructor", r.Name))
	}
	if _, dup := registrations[r.Name]; dup {
		panic(fmt.Sprintf("engines: engine %q registered twice", r.Name))
	}
	if r.Title == "" {
		r.Title = r.Name
	}
	registrations[r.Name] = r
}

// Registered returns every registered engine, sorted by name.
func Registered() []Registration {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Registration, 0, len(registrations))
	for _, r := range registrations {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns the names of the registered engines, sorted.
func Names() []string {
	regs := Registered()
	out := make([]string, len(regs))
	for i, r := range regs {
		out[i] = r.Name
	}
	return out
}

// IsRegistered reports whether an engine with this name is linked in.
func IsRegistered(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := registrations[name]
	return ok
}

// Describe builds the public description of a registration. eng is the
// adapter instance, used for its policy types.
func (r Registration) Describe(eng policy.Engine, enabled bool) Info {
	return Info{
		Name: r.Name, Title: r.Title, Description: r.Description,
		PolicyTypes: eng.SupportedPolicyTypes(), SourceFormat: r.SourceFormat,
		NativeExceptions: r.NativeExceptions, Limitations: r.Limitations,
		UpstreamVersion: moduleVersion(r.Module), Enabled: enabled,
	}
}

// moduleVersion looks up the version of a linked Go module.
func moduleVersion(path string) string {
	if path == "" {
		return ""
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range bi.Deps {
		if dep.Path == path {
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			return dep.Version
		}
	}
	return ""
}
