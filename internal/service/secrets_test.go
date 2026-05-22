package service

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/oguzhane/sopsgate/internal/store"
)

func setupService(t *testing.T) *SecretsService {
	t.Helper()
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not found")
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
	return NewSecretsService(sopsEngine, gitStore)
}

func TestSecretsService_CreateNamespace(t *testing.T) {
	svc := setupService(t)

	if err := svc.CreateNamespace("myapp", "tester"); err != nil {
		t.Fatal(err)
	}

	nss, err := svc.ListNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(nss) != 1 || nss[0] != "myapp" {
		t.Fatalf("expected [myapp], got %v", nss)
	}
}

func TestSecretsService_CreateNamespace_Duplicate(t *testing.T) {
	svc := setupService(t)

	svc.CreateNamespace("dup", "tester")
	err := svc.CreateNamespace("dup", "tester")
	if err == nil {
		t.Fatal("expected error for duplicate namespace")
	}
}

func TestSecretsService_DeleteNamespace(t *testing.T) {
	svc := setupService(t)

	svc.CreateNamespace("delme", "tester")
	if err := svc.DeleteNamespace("delme", "tester"); err != nil {
		t.Fatal(err)
	}

	nss, _ := svc.ListNamespaces()
	if len(nss) != 0 {
		t.Fatalf("expected 0, got %v", nss)
	}
}

func TestSecretsService_DeleteNamespace_NotFound(t *testing.T) {
	svc := setupService(t)

	err := svc.DeleteNamespace("nonexistent", "tester")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent namespace")
	}
}

func TestSecretsService_PutAndGetSecret(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	if err := svc.PutSecret("app", "password", "secret123", "tester"); err != nil {
		t.Fatal(err)
	}

	secret, err := svc.GetSecret("app", "password")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "secret123" {
		t.Fatalf("expected 'secret123', got %q", secret.Value)
	}
	if secret.Namespace != "app" {
		t.Fatalf("expected namespace 'app', got %q", secret.Namespace)
	}
	if secret.Key != "password" {
		t.Fatalf("expected key 'password', got %q", secret.Key)
	}
	if secret.Version == "" {
		t.Fatal("version should be set")
	}
}

func TestSecretsService_PutSecret_NamespaceNotFound(t *testing.T) {
	svc := setupService(t)

	err := svc.PutSecret("nosuchns", "key", "val", "tester")
	if err == nil {
		t.Fatal("expected error for missing namespace")
	}
}

func TestSecretsService_GetSecret_KeyNotFound(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	_, err := svc.GetSecret("app", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestSecretsService_ListKeys(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	svc.PutSecret("app", "key_b", "v1", "tester")
	svc.PutSecret("app", "key_a", "v2", "tester")

	keys, err := svc.ListKeys("app")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	// Should be sorted
	if keys[0] != "key_a" || keys[1] != "key_b" {
		t.Fatalf("expected [key_a, key_b], got %v", keys)
	}
}

func TestSecretsService_GetAllSecrets(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	svc.PutSecret("app", "k1", "v1", "tester")
	svc.PutSecret("app", "k2", "v2", "tester")

	secrets, err := svc.GetAllSecrets("app")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2, got %d", len(secrets))
	}
	if secrets["k1"] != "v1" || secrets["k2"] != "v2" {
		t.Fatalf("unexpected: %v", secrets)
	}
}

func TestSecretsService_BulkPutSecrets(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	err := svc.BulkPutSecrets("app", map[string]string{"a": "1", "b": "2", "c": "3"}, "tester")
	if err != nil {
		t.Fatal(err)
	}

	secrets, _ := svc.GetAllSecrets("app")
	if len(secrets) != 3 {
		t.Fatalf("expected 3, got %d", len(secrets))
	}
}

func TestSecretsService_DeleteSecret(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")
	svc.PutSecret("app", "k1", "v1", "tester")
	svc.PutSecret("app", "k2", "v2", "tester")

	if err := svc.DeleteSecret("app", "k1", "tester"); err != nil {
		t.Fatal(err)
	}

	keys, _ := svc.ListKeys("app")
	if len(keys) != 1 || keys[0] != "k2" {
		t.Fatalf("expected [k2], got %v", keys)
	}
}

func TestSecretsService_DeleteSecret_NotFound(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")

	err := svc.DeleteSecret("app", "nonexistent", "tester")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestSecretsService_GetVersions(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")
	svc.PutSecret("app", "k", "v1", "tester")
	svc.PutSecret("app", "k", "v2", "tester")

	versions, err := svc.GetVersions("app", "k")
	if err != nil {
		t.Fatal(err)
	}
	// Namespace was created (1 commit) + 2 put operations = 3 commits
	if len(versions) < 2 {
		t.Fatalf("expected >= 2 versions, got %d", len(versions))
	}
}

func TestSecretsService_GetSecretAtVersion(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("app", "tester")
	svc.PutSecret("app", "k", "first", "tester")
	svc.PutSecret("app", "k", "second", "tester")

	versions, _ := svc.GetVersions("app", "k")
	// versions[0] is latest (second), versions[1] is older, etc.
	// Find the version with "first" value — it's an earlier commit.
	// The last version in the list should be the namespace create commit.
	// versions[len-2] should be first PUT, versions[0] should be latest PUT.

	oldVersion := versions[len(versions)-2].Version // first PUT commit
	secret, err := svc.GetSecretAtVersion("app", "k", oldVersion)
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "first" {
		t.Fatalf("expected 'first', got %q", secret.Value)
	}
}

func TestSecretsService_ConcurrentNamespaceWrites(t *testing.T) {
	svc := setupService(t)

	// Create two namespaces
	svc.CreateNamespace("ns1", "tester")
	svc.CreateNamespace("ns2", "tester")

	// Concurrent writes to different namespaces should all succeed
	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := range 10 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if err := svc.PutSecret("ns1", "k", fmt.Sprintf("v1-%d", i), "tester"); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if err := svc.PutSecret("ns2", "k", fmt.Sprintf("v2-%d", i), "tester"); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}
}

func TestSecretsService_ConcurrentSameNamespaceWrites(t *testing.T) {
	svc := setupService(t)
	svc.CreateNamespace("shared", "tester")

	// Concurrent writes to the same namespace + same key should serialize
	var wg sync.WaitGroup
	errs := make(chan error, 10)

	for i := range 5 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := svc.PutSecret("shared", "thekey", fmt.Sprintf("val-%d", i), "tester"); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent same-namespace write error: %v", err)
	}

	// Verify the key exists and has a value
	secret, err := svc.GetSecret("shared", "thekey")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value == "" {
		t.Fatal("expected a value after concurrent writes")
	}
}

func TestSecretsService_NestedNamespace(t *testing.T) {
	svc := setupService(t)

	if err := svc.CreateNamespace("infra/postgres", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := svc.PutSecret("infra/postgres", "password", "pg123", "tester"); err != nil {
		t.Fatal(err)
	}

	secret, err := svc.GetSecret("infra/postgres", "password")
	if err != nil {
		t.Fatal(err)
	}
	if secret.Value != "pg123" {
		t.Fatalf("expected 'pg123', got %q", secret.Value)
	}

	nss, _ := svc.ListNamespaces()
	found := false
	for _, ns := range nss {
		if ns == "infra/postgres" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected infra/postgres in namespaces, got %v", nss)
	}
}
