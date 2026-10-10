// Package oidc provides a minimal, generic OIDC configuration and callback
// scaffold for enterprise single-sign-on. This is intentionally lightweight
// to keep scope small while matching Workstream 2's "generic OIDC first"
// requirement.
package oidc

import (
	"context"
	"errors"
	"net/url"
	"time"
)

// Config describes a generic OIDC provider.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	ClockSkew     time.Duration
	AllowInsecure bool
}

var (
	ErrInvalidConfig = errors.New("oidc: invalid config")
	ErrNoToken       = errors.New("oidc: no token returned")
)

// Provider is a minimal OIDC provider interface.
type Provider interface {
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*Token, error)
}

// Token represents a minimal ID token response.
type Token struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
	Subject      string
	Email        string
	Claims       map[string]any
}

// DefaultConfig returns a safe default configuration template.
func DefaultConfig() Config {
	return Config{
		Scopes:    []string{"openid", "profile", "email"},
		ClockSkew: 30 * time.Second,
	}
}

// AuthURL builds the authorization URL for the generic provider.
func (c Config) AuthURL(state string) string {
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURI == "" {
		return ""
	}
	u, _ := url.Parse(c.Issuer)
	if u == nil {
		return ""
	}
	// This is a scaffold: callers integrate with actual discovery if needed.
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("scope", join(c.Scopes, " "))
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func join(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}