package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oergin/sopsgate/internal/model"
)

func TestTokenAuth_ValidToken(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	req.Header.Set("Authorization", "Bearer sk-test-123")

	identity, err := auth.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Name != "admin" {
		t.Fatalf("expected admin, got %s", identity.Name)
	}
}

func TestTokenAuth_InvalidToken(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	_, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestTokenAuth_MissingHeader(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	_, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestTokenAuth_BadFormat(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	req.Header.Set("Authorization", "Basic abc123")

	_, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestAuthMiddleware_BlocksUnauthenticated(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(auth)(inner)

	// No token.
	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_AllowsAuthenticated(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	var gotIdentity string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := r.Context().Value(identityKey).(*model.Identity); ok {
			gotIdentity = id.Name
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(auth)(inner)

	req := httptest.NewRequest("GET", "/api/v1/secrets/test", nil)
	req.Header.Set("Authorization", "Bearer sk-test-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotIdentity != "admin" {
		t.Fatalf("expected admin identity, got %q", gotIdentity)
	}
}

func TestAuthMiddleware_SkipsHealthz(t *testing.T) {
	auth := NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-123"},
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AuthMiddleware(auth)(inner)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for healthz, got %d", rec.Code)
	}
}
