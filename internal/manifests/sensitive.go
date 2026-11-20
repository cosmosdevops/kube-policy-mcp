package manifests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const redacted = "[REDACTED]"

// Redactor removes Secret values from text produced by policy engines.
type Redactor struct {
	values []string
}

// NewRedactor collects the data and stringData values of every Secret in the
// given resources, in both encoded and decoded form.
func NewRedactor(resources ...[]Resource) *Redactor {
	set := map[string]bool{}
	add := func(v string) {
		// Very short values would cause noisy false matches.
		if len(v) >= 6 {
			set[v] = true
		}
	}
	for _, list := range resources {
		for _, r := range list {
			if r.Kind() != "Secret" {
				continue
			}
			for _, key := range []string{"data", "stringData"} {
				m, _ := r.Object[key].(map[string]any)
				for _, v := range m {
					s, ok := v.(string)
					if !ok {
						continue
					}
					add(s)
					if key == "data" {
						if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
							add(string(dec))
						}
					}
				}
			}
		}
	}
	r := &Redactor{}
	for v := range set {
		r.values = append(r.values, v)
	}
	// Longest first so that overlapping values are fully removed.
	sort.Slice(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
	return r
}

// Clean redacts secret values, strips control characters and bounds length.
func (r *Redactor) Clean(s string, max int) string {
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, redacted)
	}
	s = strings.Map(func(c rune) rune {
		if c == '\n' || c == '\t' {
			return ' '
		}
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, s)
	if max > 0 && len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "… [truncated]"
	}
	return s
}

// CleanValue redacts every string inside an arbitrary JSON-like value.
func (r *Redactor) CleanValue(v any, max int) any {
	switch t := v.(type) {
	case string:
		return r.Clean(t, max)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = r.CleanValue(x, max)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.CleanValue(x, max)
		}
		return out
	}
	return v
}

// Observed returns a short, safe rendering of the value at a field path such
// as "spec.template.spec.containers[0].image". Secret payloads are masked.
// found is false when the field is not set.
func Observed(r Resource, field string, red *Redactor) (value string, found bool) {
	if field == "" {
		return "", false
	}
	v, ok := Lookup(r.Object, field)
	if !ok {
		return "", false
	}
	if r.Kind() == "Secret" && (strings.HasPrefix(field, "data") || strings.HasPrefix(field, "stringData")) {
		return redacted, true
	}
	var s string
	switch t := v.(type) {
	case string:
		s = strconv.Quote(t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			s = fmt.Sprint(v)
		} else {
			s = string(b)
		}
	}
	return red.Clean(s, 600), true
}

// Lookup resolves a dotted field path with optional [index] parts.
func Lookup(obj any, field string) (any, bool) {
	cur := obj
	for _, part := range splitPath(field) {
		if part.key != "" {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[part.key]
			if !ok {
				return nil, false
			}
		}
		if part.index >= 0 {
			l, ok := cur.([]any)
			if !ok || part.index >= len(l) {
				return nil, false
			}
			cur = l[part.index]
		}
	}
	return cur, true
}

type pathPart struct {
	key   string
	index int
}

func splitPath(field string) []pathPart {
	var parts []pathPart
	for _, seg := range strings.Split(field, ".") {
		if seg == "" {
			continue
		}
		key := seg
		var idxs []int
		for strings.HasSuffix(key, "]") {
			open := strings.LastIndex(key, "[")
			if open < 0 {
				break
			}
			n, err := strconv.Atoi(key[open+1 : len(key)-1])
			if err != nil {
				break
			}
			idxs = append([]int{n}, idxs...)
			key = key[:open]
		}
		if len(idxs) == 0 {
			parts = append(parts, pathPart{key: key, index: -1})
			continue
		}
		parts = append(parts, pathPart{key: key, index: idxs[0]})
		for _, n := range idxs[1:] {
			parts = append(parts, pathPart{index: n})
		}
	}
	return parts
}
