package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/oguzhane/sopsgate/internal/model"
)

// Authenticator validates incoming requests.
type Authenticator interface {
	Authenticate(r *http.Request) (*model.Identity, error)
}

// TokenAuth implements Authenticator using static bearer tokens.
type TokenAuth struct {
	tokens map[string]string // token -> name
}

// NewTokenAuth creates a TokenAuth from a list of token configs.
func NewTokenAuth(tokens []struct{ Name, Token string }) *TokenAuth {
	m := make(map[string]string)
	for _, t := range tokens {
		m[t.Token] = t.Name
	}
	return &TokenAuth{tokens: m}
}

// Authenticate validates a Bearer token.
func (a *TokenAuth) Authenticate(r *http.Request) (*model.Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errUnauthorized("missing authorization header")
	}
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, errUnauthorized("invalid authorization format")
	}
	token := strings.TrimPrefix(header, "Bearer ")
	name, ok := a.tokens[token]
	if !ok {
		return nil, errUnauthorized("invalid token")
	}
	return &model.Identity{Name: name}, nil
}

type authError struct {
	msg string
}

func (e *authError) Error() string { return e.msg }

func errUnauthorized(msg string) error {
	return &authError{msg: msg}
}

// AuthMiddleware wraps a handler with authentication.
func AuthMiddleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check.
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			identity, err := auth.Authenticate(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), identityKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
