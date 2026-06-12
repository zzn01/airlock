package webauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zzn01/airlock/internal/config"
)

// Claims are the identity fields airlock reads from a verified ID token: the
// stable subject, the email, and the values of the configured groups claim.
type Claims struct {
	Subject string
	Email   string
	Groups  []string
}

// Authenticator is the seam between the OIDC HTTP flow and the OAuth2/OIDC
// machinery. AuthCodeURL builds the provider authorization URL embedding the
// CSRF state and the replay-defeating nonce; Verify exchanges an authorization
// code for a verified ID token (checking signature, audience, and the nonce)
// and returns its claims. The real implementation talks to the IdP; tests
// inject a fake so the flow needs no live provider.
type Authenticator interface {
	AuthCodeURL(state, nonce string) string
	Verify(ctx context.Context, code, nonce string) (Claims, error)
}

// DeriveGroups maps an authenticated user's claims to airlock group names. An
// admin override matching the user by subject or email wins outright (its groups
// are used verbatim, the claim mapping skipped). Otherwise each value of the
// configured groups claim is mapped through GroupMapping and the results are
// unioned, de-duplicated, and returned in first-seen order. A claim value with
// no mapping entry contributes nothing (default-deny on unmapped IdP groups).
func DeriveGroups(c Claims, oidcCfg *config.OIDC) []string {
	for _, ov := range oidcCfg.Overrides {
		if (ov.Subject != "" && ov.Subject == c.Subject) || (ov.Email != "" && ov.Email == c.Email) {
			return dedupe(ov.Groups)
		}
	}
	var out []string
	seen := make(map[string]bool)
	for _, v := range c.Groups {
		for _, g := range oidcCfg.GroupMapping[v] {
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	return out
}

func dedupe(in []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, g := range in {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// OIDCProvider is the real Authenticator, built on go-oidc + oauth2: OIDC
// discovery against the issuer, authorization-code exchange, ID-token
// verification, and configured-claim extraction.
type OIDCProvider struct {
	oauth2      oauth2.Config
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
}

// NewOIDCProvider performs OIDC discovery against the issuer and constructs the
// provider. It is best-effort at the caller's discretion: discovery requires
// reaching the issuer, so an unreachable or misconfigured provider returns an
// error that the caller may log and continue from, leaving local login intact.
func NewOIDCProvider(ctx context.Context, cfg *config.OIDC) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &OIDCProvider{
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		groupsClaim: groupsClaimOrDefault(cfg.GroupsClaim),
	}, nil
}

func groupsClaimOrDefault(name string) string {
	if name == "" {
		return "groups"
	}
	return name
}

// AuthCodeURL returns the provider authorization URL embedding state and nonce.
func (p *OIDCProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth2.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Verify exchanges code for a token, verifies the contained ID token, checks
// its nonce against the expected value, and returns the identity claims.
func (p *OIDCProvider) Verify(ctx context.Context, code, nonce string) (Claims, error) {
	tok, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return Claims{}, fmt.Errorf("code exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("token response has no id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return Claims{}, fmt.Errorf("id token nonce mismatch")
	}
	var all map[string]any
	if err := idToken.Claims(&all); err != nil {
		return Claims{}, fmt.Errorf("decode id token claims: %w", err)
	}
	email, _ := all["email"].(string)
	return Claims{
		Subject: idToken.Subject,
		Email:   email,
		Groups:  claimStrings(all[p.groupsClaim]),
	}, nil
}

// claimStrings coerces a claim value into a string slice. Providers encode a
// groups/roles claim as a JSON array of strings (decoded to []any) or, for a
// single value, a bare string; anything else yields no groups.
func claimStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		return []string{t}
	default:
		return nil
	}
}

// randomToken returns a URL-safe random string with 256 bits of entropy, used
// for opaque state and nonce values in the OIDC flow.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
