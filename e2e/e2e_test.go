package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oguzhane/sopsgate/internal/api"
	"github.com/oguzhane/sopsgate/internal/model"
	"github.com/oguzhane/sopsgate/internal/service"
	"github.com/oguzhane/sopsgate/internal/store"
)

func setupServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not found, skipping E2E tests")
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
	handler := api.NewHandler(svc)

	auth := api.NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-test-token"},
	})

	router := api.NewRouter(handler, auth)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return server, "sk-test-token"
}

func doReq(t *testing.T, method, url, token string, body interface{}) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestE2E_FullLifecycle(t *testing.T) {
	srv, token := setupServer(t)

	// 1. Create namespace
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/myapp", token, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create namespace: expected 201, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 2. Create duplicate namespace → 409
	resp = doReq(t, "POST", srv.URL+"/api/v1/namespaces/myapp", token, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate namespace: expected 409, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 3. List namespaces
	resp = doReq(t, "GET", srv.URL+"/api/v1/namespaces", token, nil)
	var nsResp model.NamespacesResponse
	readJSON(t, resp, &nsResp)
	if len(nsResp.Namespaces) != 1 || nsResp.Namespaces[0] != "myapp" {
		t.Fatalf("list namespaces: expected [myapp], got %v", nsResp.Namespaces)
	}

	// 4. Put a secret
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/myapp/keys/db_password", token,
		model.PutSecretRequest{Value: "secret123"})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("put secret: expected 200, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 5. Get the secret back
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp/keys/db_password", token, nil)
	var secret model.Secret
	readJSON(t, resp, &secret)
	if secret.Value != "secret123" {
		t.Fatalf("get secret: expected 'secret123', got %q", secret.Value)
	}
	if secret.Version == "" {
		t.Fatal("expected version to be set")
	}
	firstVersion := secret.Version

	// 6. List keys
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp", token, nil)
	var keysResp model.ListKeysResponse
	readJSON(t, resp, &keysResp)
	if len(keysResp.Keys) != 1 || keysResp.Keys[0] != "db_password" {
		t.Fatalf("list keys: expected [db_password], got %v", keysResp.Keys)
	}

	// 7. Update the secret
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/myapp/keys/db_password", token,
		model.PutSecretRequest{Value: "new-secret"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update secret: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 8. Get versions
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp/keys/db_password/versions", token, nil)
	var versResp model.VersionsResponse
	readJSON(t, resp, &versResp)
	if len(versResp.Versions) < 2 {
		t.Fatalf("expected >= 2 versions, got %d", len(versResp.Versions))
	}

	// 9. Get old version
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp/keys/db_password/versions/"+firstVersion, token, nil)
	var oldSecret model.Secret
	readJSON(t, resp, &oldSecret)
	if oldSecret.Value != "secret123" {
		t.Fatalf("old version: expected 'secret123', got %q", oldSecret.Value)
	}

	// 10. Bulk get all secrets
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp?reveal=true", token, nil)
	var bulkResp model.BulkGetResponse
	readJSON(t, resp, &bulkResp)
	if bulkResp.Secrets["db_password"] != "new-secret" {
		t.Fatalf("bulk get: expected 'new-secret', got %q", bulkResp.Secrets["db_password"])
	}

	// 11. Add a second secret
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/myapp/keys/api_key", token,
		model.PutSecretRequest{Value: "key-abc"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put second secret: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 12. Delete first secret
	resp = doReq(t, "DELETE", srv.URL+"/api/v1/secrets/myapp/keys/db_password", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete secret: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 13. Verify deleted
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/myapp/keys/db_password", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted secret: expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 14. Delete namespace
	resp = doReq(t, "DELETE", srv.URL+"/api/v1/namespaces/myapp", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete namespace: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 15. Verify namespace gone
	resp = doReq(t, "GET", srv.URL+"/api/v1/namespaces", token, nil)
	readJSON(t, resp, &nsResp)
	if len(nsResp.Namespaces) != 0 {
		t.Fatalf("expected 0 namespaces after delete, got %v", nsResp.Namespaces)
	}
}

func TestE2E_Auth(t *testing.T) {
	srv, token := setupServer(t)

	// No token → 401
	resp := doReq(t, "GET", srv.URL+"/api/v1/namespaces", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad token → 401
	resp = doReq(t, "GET", srv.URL+"/api/v1/namespaces", "bad-token", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Good token → 200
	resp = doReq(t, "GET", srv.URL+"/api/v1/namespaces", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good token: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Healthz without token → 200
	resp = doReq(t, "GET", srv.URL+"/healthz", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestE2E_BulkPut(t *testing.T) {
	srv, token := setupServer(t)

	// Create namespace
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/bulk", token, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create namespace: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Bulk put
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/bulk", token,
		model.BulkPutRequest{Secrets: map[string]string{"k1": "v1", "k2": "v2", "k3": "v3"}})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("bulk put: expected 200, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Verify all keys
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/bulk?reveal=true", token, nil)
	var bulkResp model.BulkGetResponse
	readJSON(t, resp, &bulkResp)
	if len(bulkResp.Secrets) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(bulkResp.Secrets))
	}
	if bulkResp.Secrets["k1"] != "v1" || bulkResp.Secrets["k2"] != "v2" || bulkResp.Secrets["k3"] != "v3" {
		t.Fatalf("unexpected secrets: %v", bulkResp.Secrets)
	}
}

func TestE2E_ConcurrentWrites(t *testing.T) {
	srv, token := setupServer(t)

	// Create two namespaces
	for _, ns := range []string{"ns1", "ns2"} {
		resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/"+ns, token, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: expected 201, got %d", ns, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Concurrent writes to different namespaces
	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := range 10 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			resp := doReq(t, "PUT", fmt.Sprintf("%s/api/v1/secrets/ns1/keys/key%d", srv.URL, i), token,
				model.PutSecretRequest{Value: fmt.Sprintf("val%d", i)})
			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("ns1/key%d: got %d", i, resp.StatusCode)
			}
			resp.Body.Close()
		}(i)
		go func(i int) {
			defer wg.Done()
			resp := doReq(t, "PUT", fmt.Sprintf("%s/api/v1/secrets/ns2/keys/key%d", srv.URL, i), token,
				model.PutSecretRequest{Value: fmt.Sprintf("val%d", i)})
			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("ns2/key%d: got %d", i, resp.StatusCode)
			}
			resp.Body.Close()
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify all keys were written
	for _, ns := range []string{"ns1", "ns2"} {
		resp := doReq(t, "GET", srv.URL+"/api/v1/secrets/"+ns, token, nil)
		var keysResp model.ListKeysResponse
		readJSON(t, resp, &keysResp)
		if len(keysResp.Keys) != 10 {
			t.Errorf("%s: expected 10 keys, got %d: %v", ns, len(keysResp.Keys), keysResp.Keys)
		}
	}
}

func TestE2E_NestedNamespace(t *testing.T) {
	srv, token := setupServer(t)

	// Create nested namespace
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/infra/postgres", token, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create nested ns: expected 201, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Put secret
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/infra/postgres/keys/password", token,
		model.PutSecretRequest{Value: "pg-secret"})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("put nested: expected 200, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Get it back
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/infra/postgres/keys/password", token, nil)
	var secret model.Secret
	readJSON(t, resp, &secret)
	if secret.Value != "pg-secret" {
		t.Fatalf("expected 'pg-secret', got %q", secret.Value)
	}
}

func TestE2E_NotFound(t *testing.T) {
	srv, token := setupServer(t)

	// Get secret from non-existent namespace
	resp := doReq(t, "GET", srv.URL+"/api/v1/secrets/nonexistent/keys/foo", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Delete non-existent namespace
	resp = doReq(t, "DELETE", srv.URL+"/api/v1/namespaces/nonexistent", token, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestE2E_BadRequest(t *testing.T) {
	srv, token := setupServer(t)

	// Create namespace first
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/badreq", token, nil)
	resp.Body.Close()

	// Empty value
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/badreq/keys/k1", token,
		model.PutSecretRequest{Value: ""})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty value: expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Empty bulk
	resp = doReq(t, "PUT", srv.URL+"/api/v1/secrets/badreq", token,
		model.BulkPutRequest{Secrets: map[string]string{}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty bulk: expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestE2E_ConcurrentSameKeyWrites(t *testing.T) {
	srv, token := setupServer(t)

	// Create namespace
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/samekey", token, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create ns: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Concurrent writes to the SAME key in the SAME namespace
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := doReq(t, "PUT", srv.URL+"/api/v1/secrets/samekey/keys/thekey", token,
				model.PutSecretRequest{Value: fmt.Sprintf("value-%d", i)})
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				errors <- fmt.Errorf("write %d: got %d: %s", i, resp.StatusCode, body)
			}
			resp.Body.Close()
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	// Verify the key exists and has one of the written values
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/samekey/keys/thekey", token, nil)
	var secret model.Secret
	readJSON(t, resp, &secret)
	if secret.Value == "" {
		t.Fatal("expected a value after concurrent writes")
	}

	// Verify we have version history from all writes
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/samekey/keys/thekey/versions", token, nil)
	var versResp model.VersionsResponse
	readJSON(t, resp, &versResp)
	// 1 create + 10 puts = 11 commits
	if len(versResp.Versions) != 11 {
		t.Fatalf("expected 11 versions, got %d", len(versResp.Versions))
	}
}

// --- mTLS E2E Tests ---

// generateTestCA creates a self-signed CA certificate and key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caCert, caKey, caPEM
}

// generateTestCert creates a certificate signed by the given CA.
func generateTestCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isServer bool) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert, certPEM
}

func setupMTLSServer(t *testing.T) (serverURL, token string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte) {
	t.Helper()

	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not found, skipping E2E tests")
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "age.key")
	cmd := exec.Command("age-keygen", "-o", keyFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("age-keygen: %v\n%s", err, out)
	}

	sopsEngine, err := store.NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}
	gitStore, err := store.NewGitStore(filepath.Join(dir, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.NewSecretsService(sopsEngine, gitStore)
	handler := api.NewHandler(svc)
	auth := api.NewTokenAuth([]struct{ Name, Token string }{
		{Name: "admin", Token: "sk-mtls-token"},
	})
	router := api.NewRouter(handler, auth)

	// Generate CA and server cert.
	caCert, caKey, caPEM = generateTestCA(t)
	serverCert, _ := generateTestCert(t, caCert, caKey, "localhost", true)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(router)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv.URL, "sk-mtls-token", caCert, caKey, caPEM
}

func TestE2E_MTLS_ValidClientCert(t *testing.T) {
	srvURL, token, caCert, caKey, caPEM := setupMTLSServer(t)

	clientCert, _ := generateTestCert(t, caCert, caKey, "test-client", false)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
			},
		},
	}

	// Valid client cert + valid token → 200
	req, _ := http.NewRequest("GET", srvURL+"/api/v1/namespaces", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request with valid client cert failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestE2E_MTLS_ValidCertNoToken(t *testing.T) {
	srvURL, _, caCert, caKey, caPEM := setupMTLSServer(t)

	clientCert, _ := generateTestCert(t, caCert, caKey, "test-client", false)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
			},
		},
	}

	// Valid client cert + no token → 401
	req, _ := http.NewRequest("GET", srvURL+"/api/v1/namespaces", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestE2E_MTLS_NoClientCert(t *testing.T) {
	srvURL, _, _, _, caPEM := setupMTLSServer(t)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
				// No client certificate.
			},
		},
	}

	// No client cert → TLS handshake error
	req, _ := http.NewRequest("GET", srvURL+"/api/v1/namespaces", nil)
	req.Header.Set("Authorization", "Bearer sk-mtls-token")
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected TLS handshake error, got nil")
	}
}

func TestE2E_GenerateSecret(t *testing.T) {
	srv, token := setupServer(t)

	// Create namespace.
	resp := doReq(t, "POST", srv.URL+"/api/v1/namespaces/gentest", token, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create namespace: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Generate a password.
	resp = doReq(t, "POST", srv.URL+"/api/v1/secrets/gentest/keys/db_password/generate", token,
		model.GenerateSecretRequest{Type: "password", Length: 24, Charset: "alphanumeric"})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("generate password: expected 201, got %d: %s", resp.StatusCode, body)
	}
	var genResp model.GenerateSecretResponse
	readJSON(t, resp, &genResp)
	if genResp.Namespace != "gentest" || genResp.Key != "db_password" {
		t.Fatalf("unexpected response: %+v", genResp)
	}
	if len(genResp.Value) != 24 {
		t.Fatalf("expected 24-char value, got %d", len(genResp.Value))
	}
	if genResp.Version == "" {
		t.Fatal("expected version to be set")
	}

	// GET to verify the stored value matches.
	resp = doReq(t, "GET", srv.URL+"/api/v1/secrets/gentest/keys/db_password", token, nil)
	var secret model.Secret
	readJSON(t, resp, &secret)
	if secret.Value != genResp.Value {
		t.Fatalf("GET value %q != generated value %q", secret.Value, genResp.Value)
	}

	// Generate a hex key.
	resp = doReq(t, "POST", srv.URL+"/api/v1/secrets/gentest/keys/hmac_key/generate", token,
		model.GenerateSecretRequest{Type: "hex", Length: 64})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("generate hex: expected 201, got %d: %s", resp.StatusCode, body)
	}
	var hexResp model.GenerateSecretResponse
	readJSON(t, resp, &hexResp)
	if len(hexResp.Value) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(hexResp.Value))
	}

	// Generate a base64 key.
	resp = doReq(t, "POST", srv.URL+"/api/v1/secrets/gentest/keys/enc_key/generate", token,
		model.GenerateSecretRequest{Type: "base64", Length: 32})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("generate base64: expected 201, got %d: %s", resp.StatusCode, body)
	}
	var b64Resp model.GenerateSecretResponse
	readJSON(t, resp, &b64Resp)
	if b64Resp.Value == "" {
		t.Fatal("expected non-empty base64 value")
	}

	// Invalid request → 400.
	resp = doReq(t, "POST", srv.URL+"/api/v1/secrets/gentest/keys/bad/generate", token,
		model.GenerateSecretRequest{Type: "invalid"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid type: expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Namespace not found → 404.
	resp = doReq(t, "POST", srv.URL+"/api/v1/secrets/nosuchns/keys/k/generate", token,
		model.GenerateSecretRequest{Type: "password"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing ns: expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
