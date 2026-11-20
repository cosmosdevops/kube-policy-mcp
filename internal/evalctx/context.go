// Package evalctx models the simulated admission context a caller supplies
// with an evaluation. Nothing here is verified against a cluster.
package evalctx

import (
	"fmt"
	"sort"
	"strings"
)

// Namespace is caller-supplied namespace metadata.
type Namespace struct {
	Name        string            `json:"name" jsonschema:"namespace name"`
	Labels      map[string]string `json:"labels,omitempty" jsonschema:"namespace labels, used by namespace selectors"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// User is the simulated requesting user.
type User struct {
	Username string   `json:"username,omitempty"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Context is the simulated evaluation context.
type Context struct {
	KubernetesVersion string `json:"kubernetesVersion,omitempty" jsonschema:"target Kubernetes version, for example 1.35"`
	// Namespace is the target namespace. Resources without a namespace are
	// treated as being deployed into it.
	Namespace *Namespace `json:"namespace,omitempty" jsonschema:"target namespace and its metadata"`
	// Namespaces describes further namespaces referenced by the manifests.
	Namespaces []Namespace `json:"namespaces,omitempty" jsonschema:"metadata for other namespaces used by the manifests"`
	Operation  string      `json:"operation,omitempty" jsonschema:"admission operation: CREATE (default), UPDATE or DELETE"`
	User       *User       `json:"user,omitempty" jsonschema:"simulated requesting user"`
	// Variables are free-form values such as environment.
	Variables map[string]any `json:"variables,omitempty" jsonschema:"free-form variables such as environment"`
	// Resources are extra Kubernetes objects that exist in the cluster and
	// that policies may look up (for example ConfigMaps).
	Resources []map[string]any `json:"resources,omitempty" jsonschema:"extra Kubernetes objects policies may look up, such as ConfigMaps"`
	// Data is arbitrary policy data. Each engine adapter documents where its
	// policies can read it.
	Data map[string]any `json:"data,omitempty" jsonschema:"arbitrary policy data"`

	// operationSet records whether the caller chose the operation.
	operationSet bool
}

// Normalize validates the context and applies defaults.
func (c *Context) Normalize() error {
	op := strings.ToUpper(strings.TrimSpace(c.Operation))
	switch op {
	case "":
		c.Operation = "CREATE"
	case "CREATE", "UPDATE", "DELETE":
		c.Operation = op
		c.operationSet = true
	default:
		return fmt.Errorf("invalid operation %q: must be CREATE, UPDATE or DELETE", c.Operation)
	}
	seen := map[string]bool{}
	if c.Namespace != nil {
		if c.Namespace.Name == "" {
			return fmt.Errorf("context.namespace.name must be set when context.namespace is given")
		}
		seen[c.Namespace.Name] = true
	}
	for _, ns := range c.Namespaces {
		if ns.Name == "" {
			return fmt.Errorf("context.namespaces entries need a name")
		}
		if seen[ns.Name] {
			return fmt.Errorf("namespace %q is described more than once in the context", ns.Name)
		}
		seen[ns.Name] = true
	}
	return nil
}

// AddNamespace registers namespace metadata unless the name is already known.
func (c *Context) AddNamespace(ns Namespace) {
	if _, ok := c.NamespaceFor(ns.Name); ok {
		return
	}
	c.Namespaces = append(c.Namespaces, ns)
}

// NamespaceFor returns the metadata known for a namespace.
func (c *Context) NamespaceFor(name string) (Namespace, bool) {
	if name == "" {
		return Namespace{}, false
	}
	if c.Namespace != nil && c.Namespace.Name == name {
		return *c.Namespace, true
	}
	for _, ns := range c.Namespaces {
		if ns.Name == name {
			return ns, true
		}
	}
	return Namespace{}, false
}

// NamespaceLabelsKnown reports whether the labels of a namespace were
// supplied. A namespace given by name only (labels omitted) does not count:
// omitted labels mean "not stated", not "no labels". Pass an empty labels
// object to state that a namespace has no labels.
func (c *Context) NamespaceLabelsKnown(name string) bool {
	ns, ok := c.NamespaceFor(name)
	return ok && ns.Labels != nil
}

// AllNamespaces returns every known namespace sorted by name.
func (c *Context) AllNamespaces() []Namespace {
	var out []Namespace
	if c.Namespace != nil {
		out = append(out, *c.Namespace)
	}
	out = append(out, c.Namespaces...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Missing returns the entries of required that the context does not provide
// for a resource in resourceNamespace. Recognised keys:
//
//	namespace            the resource's namespace is named in the context
//	namespace.labels     the labels of that namespace were supplied
//	operation            an explicitly chosen admission operation
//	user, user.groups    the simulated user
//	kubernetesVersion    the target version
//	variables.<name>     a named variable
//	data.<name>          a named policy data entry
//	resources            at least one object in context.resources, stating
//	                     what else exists in the cluster
//
// Unrecognised keys are reported as missing so they are never ignored.
func (c *Context) Missing(required []string, resourceNamespace string) []string {
	var missing []string
	for _, key := range required {
		ok := false
		switch {
		case key == "namespace":
			_, ok = c.NamespaceFor(resourceNamespace)
		case key == "namespace.labels" || key == "namespace.annotations":
			ok = c.NamespaceLabelsKnown(resourceNamespace)
		case key == "operation":
			ok = c.operationSet
		case key == "user" || key == "user.username":
			ok = c.User != nil && c.User.Username != ""
		case key == "user.groups":
			ok = c.User != nil && len(c.User.Groups) > 0
		case key == "kubernetesVersion":
			ok = c.KubernetesVersion != ""
		case strings.HasPrefix(key, "variables."):
			_, ok = c.Variables[strings.TrimPrefix(key, "variables.")]
		case strings.HasPrefix(key, "data."):
			_, ok = c.Data[strings.TrimPrefix(key, "data.")]
		case key == "resources":
			ok = len(c.Resources) > 0
		}
		if !ok {
			missing = append(missing, key)
		}
	}
	return missing
}
