// Package api implements the HTTP handlers and routing for sopsgate.
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/oguzhane/sopsgate/internal/model"
	"github.com/oguzhane/sopsgate/internal/service"
	"github.com/oguzhane/sopsgate/internal/store"
)

// Handler holds the HTTP handlers and their dependencies.
type Handler struct {
	svc *service.SecretsService
}

// NewHandler creates a new Handler.
func NewHandler(svc *service.SecretsService) *Handler {
	return &Handler{svc: svc}
}

// NewRouter creates the HTTP router with all routes.
// Because namespaces can contain slashes (e.g., "infra/postgres"),
// we use catch-all wildcards and parse the path segments manually.
func NewRouter(h *Handler, auth Authenticator) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/namespaces", h.ListNamespaces)
	mux.HandleFunc("POST /api/v1/namespaces/{rest...}", h.CreateNamespace)
	mux.HandleFunc("DELETE /api/v1/namespaces/{rest...}", h.DeleteNamespace)

	// Secrets: catch-all, then dispatch based on path structure.
	mux.HandleFunc("GET /api/v1/secrets/{rest...}", h.handleGetSecrets)
	mux.HandleFunc("PUT /api/v1/secrets/{rest...}", h.handlePutSecrets)
	mux.HandleFunc("POST /api/v1/secrets/{rest...}", h.handlePostSecrets)
	mux.HandleFunc("DELETE /api/v1/secrets/{rest...}", h.handleDeleteSecrets)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	if auth != nil {
		return AuthMiddleware(auth)(mux)
	}
	return mux
}

// parseSecretsPath parses the rest of the path after /api/v1/secrets/.
// Patterns:
//   {ns}/keys/{key}/versions/{version}  → ns, key, version
//   {ns}/keys/{key}/versions            → ns, key, "versions"
//   {ns}/keys/{key}                     → ns, key, ""
//   {ns}                                → ns, "", "" (list/bulk)
//
// The namespace can contain slashes (e.g., "infra/postgres").
// We look for "/keys/" as the delimiter between namespace and key.
func parseSecretsPath(rest string) (ns, key, extra string) {
	rest = strings.TrimSuffix(rest, "/")

	keysIdx := strings.Index(rest, "/keys/")
	if keysIdx == -1 {
		// No /keys/ → the entire rest is the namespace.
		return rest, "", ""
	}

	ns = rest[:keysIdx]
	afterKeys := rest[keysIdx+6:] // after "/keys/"

	// afterKeys could be:
	//   "mykey"
	//   "mykey/versions"
	//   "mykey/versions/abc1234"
	//   "mykey/generate"
	versionsIdx := strings.Index(afterKeys, "/versions")
	if versionsIdx != -1 {
		key = afterKeys[:versionsIdx]
		afterVersions := afterKeys[versionsIdx+9:] // after "/versions"
		if afterVersions == "" || afterVersions == "/" {
			return ns, key, "versions"
		}
		// Strip leading slash from version hash.
		return ns, key, strings.TrimPrefix(afterVersions, "/")
	}

	generateIdx := strings.Index(afterKeys, "/generate")
	if generateIdx != -1 {
		key = afterKeys[:generateIdx]
		return ns, key, "generate"
	}

	return ns, afterKeys, ""
}

// --- GET dispatcher ---

func (h *Handler) handleGetSecrets(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	ns, key, extra := parseSecretsPath(rest)

	switch {
	case key == "" && extra == "":
		// GET /api/v1/secrets/{ns}[?reveal=true]
		h.ListOrGetSecrets(w, r, ns)
	case key != "" && extra == "":
		// GET /api/v1/secrets/{ns}/keys/{key}
		h.GetSecret(w, r, ns, key)
	case key != "" && extra == "versions":
		// GET /api/v1/secrets/{ns}/keys/{key}/versions
		h.GetVersions(w, r, ns, key)
	case key != "" && extra != "":
		// GET /api/v1/secrets/{ns}/keys/{key}/versions/{version}
		h.GetSecretAtVersion(w, r, ns, key, extra)
	default:
		writeError(w, http.StatusBadRequest, "invalid path")
	}
}

// --- PUT dispatcher ---

func (h *Handler) handlePutSecrets(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	ns, key, _ := parseSecretsPath(rest)

	if key == "" {
		h.BulkPutSecrets(w, r, ns)
	} else {
		h.PutSecret(w, r, ns, key)
	}
}

// --- DELETE dispatcher ---

func (h *Handler) handleDeleteSecrets(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	ns, key, _ := parseSecretsPath(rest)

	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required for DELETE")
		return
	}
	h.DeleteSecret(w, r, ns, key)
}

// --- POST dispatcher ---

func (h *Handler) handlePostSecrets(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	ns, key, extra := parseSecretsPath(rest)

	if key != "" && extra == "generate" {
		h.GenerateSecret(w, r, ns, key)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid path")
}

// --- Namespace Handlers ---

func (h *Handler) ListNamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := h.svc.ListNamespaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.NamespacesResponse{Namespaces: namespaces})
}

func (h *Handler) CreateNamespace(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSuffix(r.PathValue("rest"), "/")
	author := identityFromContext(r)

	if err := h.svc.CreateNamespace(ns, author); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) DeleteNamespace(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSuffix(r.PathValue("rest"), "/")
	author := identityFromContext(r)

	if err := h.svc.DeleteNamespace(ns, author); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// --- Secret Handlers ---

func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request, ns, key string) {
	secret, err := h.svc.GetSecret(ns, key)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

func (h *Handler) PutSecret(w http.ResponseWriter, r *http.Request, ns, key string) {
	author := identityFromContext(r)

	var req model.PutSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	if err := h.svc.PutSecret(ns, key, req.Value, author); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request, ns, key string) {
	author := identityFromContext(r)

	if err := h.svc.DeleteSecret(ns, key, author); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GenerateSecret(w http.ResponseWriter, r *http.Request, ns, key string) {
	author := identityFromContext(r)

	var req model.GenerateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	genReq := store.GenerateRequest{
		Type:    req.Type,
		Length:  req.Length,
		Charset: req.Charset,
	}

	resp, err := h.svc.GenerateSecret(ns, key, genReq, author)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "must be") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) ListOrGetSecrets(w http.ResponseWriter, r *http.Request, ns string) {
	reveal := r.URL.Query().Get("reveal") == "true"

	if reveal {
		secrets, err := h.svc.GetAllSecrets(ns)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer store.ZeroSecretMap(secrets)
		// Convert []byte values to strings at the HTTP response boundary.
		strSecrets := make(map[string]string, len(secrets))
		for k, v := range secrets {
			strSecrets[k] = string(v)
		}
		writeJSON(w, http.StatusOK, model.BulkGetResponse{Namespace: ns, Secrets: strSecrets})
		return
	}

	keys, err := h.svc.ListKeys(ns)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.ListKeysResponse{Namespace: ns, Keys: keys})
}

func (h *Handler) BulkPutSecrets(w http.ResponseWriter, r *http.Request, ns string) {
	author := identityFromContext(r)

	var req model.BulkPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Secrets) == 0 {
		writeError(w, http.StatusBadRequest, "secrets map is required")
		return
	}

	if err := h.svc.BulkPutSecrets(ns, req.Secrets, author); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetVersions(w http.ResponseWriter, r *http.Request, ns, key string) {
	versions, err := h.svc.GetVersions(ns, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, model.VersionsResponse{Namespace: ns, Key: key, Versions: versions})
}

func (h *Handler) GetSecretAtVersion(w http.ResponseWriter, r *http.Request, ns, key, version string) {
	secret, err := h.svc.GetSecretAtVersion(ns, key, version)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(model.ErrorResponse{Error: http.StatusText(status), Message: message})
}

type contextKey string

const identityKey contextKey = "identity"

func identityFromContext(r *http.Request) string {
	if id, ok := r.Context().Value(identityKey).(*model.Identity); ok {
		return id.Name
	}
	return "anonymous"
}
