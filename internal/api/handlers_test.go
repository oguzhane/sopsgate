package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oguzhane/sopsgate/internal/model"
	"github.com/oguzhane/sopsgate/internal/service"
	"github.com/oguzhane/sopsgate/internal/store"
	"os/exec"
	"path/filepath"
)

// setupHandlerTest creates a real service backed by temp dir for handler tests.
func setupHandlerTest(t *testing.T) (*Handler, *httptest.Server) {
	t.Helper()

	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not found, skipping handler tests")
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "age.key")
	cmd := exec.Command("age-keygen", "-o", keyFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("age-keygen: %v\n%s", err, out)
	}

	repoPath := filepath.Join(dir, "repo")
	sopsEngine, err := store.NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}
	gitStore, err := store.NewGitStore(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.NewSecretsService(sopsEngine, gitStore)
	handler := NewHandler(svc)
	router := NewRouter(handler, nil) // no auth for handler unit tests
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return handler, server
}

func TestHandler_ListNamespaces_Empty(t *testing.T) {
	_, srv := setupHandlerTest(t)

	resp, err := http.Get(srv.URL + "/api/v1/namespaces")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body model.NamespacesResponse
	json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Namespaces) != 0 {
		t.Fatalf("expected 0 namespaces, got %d", len(body.Namespaces))
	}
}

func TestHandler_CreateNamespace_Success(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/testns", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestHandler_CreateNamespace_Duplicate(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/dup", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/namespaces/dup", nil)
	resp, err = http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestHandler_DeleteNamespace_NotFound(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("DELETE", srv.URL+"/api/v1/namespaces/nonexistent", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandler_PutSecret_Success(t *testing.T) {
	_, srv := setupHandlerTest(t)

	// Create namespace first
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/puttest", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Put secret
	body, _ := json.Marshal(model.PutSecretRequest{Value: "mysecret"})
	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/puttest/keys/mykey", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHandler_PutSecret_EmptyValue(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/emptyval", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	body, _ := json.Marshal(model.PutSecretRequest{Value: ""})
	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/emptyval/keys/mykey", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var errResp model.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Message != "value is required" {
		t.Fatalf("expected 'value is required', got %q", errResp.Message)
	}
}

func TestHandler_PutSecret_InvalidBody(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/badbody", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/badbody/keys/mykey", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_PutSecret_NamespaceNotFound(t *testing.T) {
	_, srv := setupHandlerTest(t)

	body, _ := json.Marshal(model.PutSecretRequest{Value: "val"})
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/secrets/nosuchns/keys/mykey", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandler_GetSecret_Success(t *testing.T) {
	_, srv := setupHandlerTest(t)

	// Create ns + secret
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/gettest", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	body, _ := json.Marshal(model.PutSecretRequest{Value: "hello"})
	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/gettest/keys/k1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()

	// Get it
	resp, err := http.Get(srv.URL + "/api/v1/secrets/gettest/keys/k1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify JSON shape
	var secret model.Secret
	json.NewDecoder(resp.Body).Decode(&secret)
	if secret.Namespace != "gettest" {
		t.Fatalf("expected namespace 'gettest', got %q", secret.Namespace)
	}
	if secret.Key != "k1" {
		t.Fatalf("expected key 'k1', got %q", secret.Key)
	}
	if secret.Value != "hello" {
		t.Fatalf("expected value 'hello', got %q", secret.Value)
	}
	if secret.Version == "" {
		t.Fatal("expected version to be set")
	}
	if secret.UpdatedAt.IsZero() {
		t.Fatal("expected updated_at to be set")
	}

	// Verify Content-Type
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

func TestHandler_GetSecret_NotFound(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/getnf", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	resp, err := http.Get(srv.URL + "/api/v1/secrets/getnf/keys/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var errResp model.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "Not Found" {
		t.Fatalf("expected error 'Not Found', got %q", errResp.Error)
	}
}

func TestHandler_DeleteSecret_NotFound(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/delns", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	req, _ = http.NewRequest("DELETE", srv.URL+"/api/v1/secrets/delns/keys/nope", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandler_ListKeys_Empty(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/listns", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	resp, err := http.Get(srv.URL + "/api/v1/secrets/listns")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body model.ListKeysResponse
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Namespace != "listns" {
		t.Fatalf("expected namespace 'listns', got %q", body.Namespace)
	}
	if len(body.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(body.Keys))
	}
}

func TestHandler_BulkPut_EmptySecrets(t *testing.T) {
	_, srv := setupHandlerTest(t)

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/bulkns", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	body, _ := json.Marshal(model.BulkPutRequest{Secrets: map[string]string{}})
	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/bulkns", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_GetVersions_ResponseShape(t *testing.T) {
	_, srv := setupHandlerTest(t)

	// Create ns + two versions
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/verns", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	for _, v := range []string{"v1", "v2"} {
		body, _ := json.Marshal(model.PutSecretRequest{Value: v})
		req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/verns/keys/k", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, _ = http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	resp, err := http.Get(srv.URL + "/api/v1/secrets/verns/keys/k/versions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body model.VersionsResponse
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Namespace != "verns" {
		t.Fatalf("expected namespace 'verns', got %q", body.Namespace)
	}
	if body.Key != "k" {
		t.Fatalf("expected key 'k', got %q", body.Key)
	}
	if len(body.Versions) < 2 {
		t.Fatalf("expected >= 2 versions, got %d", len(body.Versions))
	}
	for _, v := range body.Versions {
		if v.Version == "" {
			t.Fatal("version hash should not be empty")
		}
		if v.CommittedAt.IsZero() {
			t.Fatal("committed_at should not be zero")
		}
		if v.Message == "" {
			t.Fatal("message should not be empty")
		}
	}
}

func TestHandler_Healthz(t *testing.T) {
	_, srv := setupHandlerTest(t)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHandler_RevealSecrets_ResponseShape(t *testing.T) {
	_, srv := setupHandlerTest(t)

	// Create ns + secrets
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/namespaces/revealns", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	body, _ := json.Marshal(model.BulkPutRequest{Secrets: map[string]string{"a": "1", "b": "2"}})
	req, _ = http.NewRequest("PUT", srv.URL+"/api/v1/secrets/revealns", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()

	resp, err := http.Get(srv.URL + "/api/v1/secrets/revealns?reveal=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var bulkResp model.BulkGetResponse
	json.NewDecoder(resp.Body).Decode(&bulkResp)
	if bulkResp.Namespace != "revealns" {
		t.Fatalf("expected namespace 'revealns', got %q", bulkResp.Namespace)
	}
	if len(bulkResp.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(bulkResp.Secrets))
	}
	if bulkResp.Secrets["a"] != "1" || bulkResp.Secrets["b"] != "2" {
		t.Fatalf("unexpected secrets: %v", bulkResp.Secrets)
	}
}
