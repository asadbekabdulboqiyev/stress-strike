// Package secrets resolves configuration values containing environment
// variable references. The default implementation only reads from the
// environment; enterprise deployments can swap in Vault/AWS SM/Azure KV.
package secrets

import (
	"os"
	"strings"
)

// Resolver resolves a raw value to its final value.
type Resolver interface {
	Resolve(string) string
}

// EnvResolver resolves ${VAR} and ${VAR:-default} from the environment.
type EnvResolver struct{}

// Resolve expands environment variables in s.
func (EnvResolver) Resolve(s string) string {
	if s == "" {
		return s
	}
	return os.Expand(s, func(k string) string {
		if strings.Contains(k, ":") {
			parts := strings.SplitN(k, ":-", 2)
			if len(parts) == 2 {
				if v := os.Getenv(parts[0]); v != "" {
					return v
				}
				return parts[1]
			}
		}
		return os.Getenv(k)
	})
}

// Resolve is a convenience wrapper using EnvResolver.
func Resolve(s string) string {
	var r EnvResolver
	return r.Resolve(s)
}
