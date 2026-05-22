package store

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// generateAgeKey creates a temp age key file for testing and returns the path.
func generateAgeKey(t *testing.T) string {
	t.Helper()

	// Check if age-keygen is available.
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not found, skipping SOPS tests")
	}

	keyFile := filepath.Join(t.TempDir(), "age.key")
	cmd := exec.Command("age-keygen", "-o", keyFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("age-keygen failed: %v\n%s", err, out)
	}
	return keyFile
}

func TestSOPSEngine_NewEngine(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if engine == nil {
		t.Fatal("expected engine")
	}
}

func TestSOPSEngine_NewEngine_BadKeyFile(t *testing.T) {
	_, err := NewSOPSEngine([]string{"/nonexistent/key.txt"})
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestSOPSEngine_NewEngine_InvalidKey(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(tmpFile, []byte("not a valid age key"), 0600)
	_, err := NewSOPSEngine([]string{tmpFile})
	if err == nil {
		t.Fatal("expected error for invalid key file")
	}
}

func TestSOPSEngine_EncryptDecryptRoundTrip(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	secrets := map[string]string{
		"db_password": "super-secret",
		"api_key":     "key-123",
	}

	// Encrypt.
	encrypted, err := engine.EncryptMap(secrets, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) == 0 {
		t.Fatal("expected encrypted data")
	}

	// Decrypt.
	decrypted, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted["db_password"] != "super-secret" {
		t.Fatalf("expected 'super-secret', got %q", decrypted["db_password"])
	}
	if decrypted["api_key"] != "key-123" {
		t.Fatalf("expected 'key-123', got %q", decrypted["api_key"])
	}
}

func TestSOPSEngine_SetSecret(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// Create initial file.
	encrypted, err := engine.EncryptMap(map[string]string{"key1": "val1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set a new key.
	encrypted, err = engine.SetSecret(encrypted, "key2", "val2")
	if err != nil {
		t.Fatal(err)
	}

	// Verify both keys exist.
	secrets, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if secrets["key1"] != "val1" || secrets["key2"] != "val2" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
}

func TestSOPSEngine_DeleteSecret(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string]string{"key1": "val1", "key2": "val2"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err = engine.DeleteSecret(encrypted, "key1")
	if err != nil {
		t.Fatal(err)
	}

	secrets, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := secrets["key1"]; ok {
		t.Fatal("key1 should be deleted")
	}
	if secrets["key2"] != "val2" {
		t.Fatalf("key2 should still exist, got %v", secrets)
	}
}

func TestSOPSEngine_DeleteSecret_NotFound(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string]string{"key1": "val1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.DeleteSecret(encrypted, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestSOPSEngine_GetSecret(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string]string{"key1": "val1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	val, err := engine.GetSecret(encrypted, "key1")
	if err != nil {
		t.Fatal(err)
	}
	if val != "val1" {
		t.Fatalf("expected 'val1', got %q", val)
	}

	_, err = engine.GetSecret(encrypted, "missing")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestSOPSEngine_ListKeys(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string]string{"b_key": "v1", "a_key": "v2"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := engine.ListKeys(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "a_key" || keys[1] != "b_key" {
		t.Fatalf("expected sorted keys [a_key, b_key], got %v", keys)
	}
}

func TestSOPSEngine_CreateEmptyEncryptedFile(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.CreateEmptyEncryptedFile(nil)
	if err != nil {
		t.Fatal(err)
	}

	secrets, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected empty secrets, got %v", secrets)
	}
}

func TestSOPSEngine_UpdateExistingFile(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// Create file.
	encrypted, err := engine.EncryptMap(map[string]string{"key1": "val1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Update with new map (re-using existing encrypted metadata).
	newSecrets := map[string]string{"key1": "updated", "key2": "new"}
	encrypted, err = engine.EncryptMap(newSecrets, encrypted, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted["key1"] != "updated" || decrypted["key2"] != "new" {
		t.Fatalf("unexpected: %v", decrypted)
	}
}

// TestSOPSEngine_NeverReturnsPlaintext verifies the critical security invariant:
// every function whose output feeds into GitStore.WriteFile must return ciphertext
// that does NOT contain any plaintext secret values. This ensures plaintext only
// ever exists in memory and is never written to disk.
func TestSOPSEngine_NeverReturnsPlaintext(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// Use distinct, identifiable plaintext values that would be easy to spot in ciphertext.
	plaintexts := map[string]string{
		"db_password": "PLAINTEXT_PASSWORD_abc123",
		"api_key":     "PLAINTEXT_APIKEY_xyz789",
		"token":       "PLAINTEXT_TOKEN_secret42",
	}

	assertNoCleartext := func(t *testing.T, label string, data []byte) {
		t.Helper()
		for key, val := range plaintexts {
			if bytes.Contains(data, []byte(val)) {
				t.Fatalf("[%s] plaintext value for %q found in output — security invariant violated", label, key)
			}
		}
	}

	// 1. EncryptMap (new file) — output must be ciphertext only.
	encrypted, err := engine.EncryptMap(plaintexts, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNoCleartext(t, "EncryptMap-new", encrypted)

	// 2. EncryptMap (update existing) — output must be ciphertext only.
	updated := map[string]string{
		"db_password": "PLAINTEXT_UPDATED_newpass",
		"api_key":     "PLAINTEXT_APIKEY_xyz789",
		"token":       "PLAINTEXT_TOKEN_secret42",
	}
	reencrypted, err := engine.EncryptMap(updated, encrypted, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNoCleartext(t, "EncryptMap-update", reencrypted)
	if bytes.Contains(reencrypted, []byte("PLAINTEXT_UPDATED_newpass")) {
		t.Fatal("EncryptMap-update: updated plaintext found in output")
	}

	// 3. SetSecret — output must be ciphertext only.
	afterSet, err := engine.SetSecret(encrypted, "new_key", "PLAINTEXT_NEWKEY_val999")
	if err != nil {
		t.Fatal(err)
	}
	assertNoCleartext(t, "SetSecret", afterSet)
	if bytes.Contains(afterSet, []byte("PLAINTEXT_NEWKEY_val999")) {
		t.Fatal("SetSecret: new plaintext found in output")
	}

	// 4. DeleteSecret — output must be ciphertext only (remaining secrets still encrypted).
	afterDelete, err := engine.DeleteSecret(encrypted, "api_key")
	if err != nil {
		t.Fatal(err)
	}
	assertNoCleartext(t, "DeleteSecret", afterDelete)

	// 5. CreateEmptyEncryptedFile — sanity check, should have no values at all.
	empty, err := engine.CreateEmptyEncryptedFile(nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNoCleartext(t, "CreateEmptyEncryptedFile", empty)

	// 6. Verify the encrypted data is still valid by decrypting.
	decrypted, err := engine.DecryptFile(afterSet)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted["new_key"] != "PLAINTEXT_NEWKEY_val999" {
		t.Fatalf("expected new_key value after decrypt, got %q", decrypted["new_key"])
	}
}

func TestSOPSEngine_MultipleIdentities(t *testing.T) {
	keyFileA := generateAgeKey(t)
	keyFileB := generateAgeKey(t)

	// Encrypt with key A only.
	engineA, err := NewSOPSEngine([]string{keyFileA})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := engineA.EncryptMap(map[string]string{"secret": "multi-key-test"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with engine loaded with both A and B — should succeed.
	engineAB, err := NewSOPSEngine([]string{keyFileA, keyFileB})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := engineAB.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if secrets["secret"] != "multi-key-test" {
		t.Fatalf("expected 'multi-key-test', got %q", secrets["secret"])
	}

	// Decrypt with key B only — should fail (file was encrypted for A's recipient).
	engineB, err := NewSOPSEngine([]string{keyFileB})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engineB.DecryptFile(encrypted)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestSOPSEngine_KeyGroupsForFile(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// No repo path set — should return nil.
	groups, err := engine.KeyGroupsForFile("myapp")
	if err != nil {
		t.Fatal(err)
	}
	if groups != nil {
		t.Fatal("expected nil key groups when no repo path set")
	}

	// Set repo path to a dir without .sops.yaml — should return nil.
	dir := t.TempDir()
	engine.SetRepoPath(dir)
	groups, err = engine.KeyGroupsForFile("myapp")
	if err != nil {
		t.Fatal(err)
	}
	if groups != nil {
		t.Fatal("expected nil key groups when no .sops.yaml exists")
	}

	// Create a .sops.yaml with age creation rules.
	sopsConfig := `creation_rules:
  - path_regex: secrets/prod\..*
    age: 'age1yt3tfqlfrwdwx0z0ynwplcr6qxcxfaqycuprpmy89nr83ltx74tqdpszlw'
  - age: 'age1s3cqcks5genc6ru8chl0hkkd04zmxvczsvdxq99ekffe4gmvjpzsedk23c'
`
	os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(sopsConfig), 0644)

	// "prod" namespace should match the first rule.
	groups, err = engine.KeyGroupsForFile("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("expected key groups for prod namespace")
	}

	// "dev" namespace should match the default rule.
	groups, err = engine.KeyGroupsForFile("dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("expected key groups for dev namespace (default rule)")
	}
}

func TestParseAgeRecipients(t *testing.T) {
	data := []byte("# created: 2024-01-01\n# public key: age1abc123def456\nAGE-SECRET-KEY-1XXXXX\n")
	recipients, err := parseAgeRecipients(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0] != "age1abc123def456" {
		t.Fatalf("unexpected recipients: %v", recipients)
	}
}

func TestParseAgeRecipients_None(t *testing.T) {
	data := []byte("no public key here\n")
	_, err := parseAgeRecipients(data)
	if err == nil {
		t.Fatal("expected error for no recipients")
	}
}

func TestSOPSEngine_DecryptCorruptData(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	// Completely invalid data
	_, err = engine.DecryptFile([]byte("not valid sops yaml at all"))
	if err == nil {
		t.Fatal("expected error for corrupt data")
	}

	// Valid YAML but not SOPS-encrypted
	_, err = engine.DecryptFile([]byte("key: value\n"))
	if err == nil {
		t.Fatal("expected error for non-SOPS YAML")
	}

	// Empty data
	_, err = engine.DecryptFile([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty data")
	}

	// Truncated SOPS file — starts valid but incomplete
	encrypted, _ := engine.EncryptMap(map[string]string{"k": "v"}, nil, nil)
	truncated := encrypted[:len(encrypted)/2]
	_, err = engine.DecryptFile(truncated)
	if err == nil {
		t.Fatal("expected error for truncated encrypted data")
	}
}

func TestSOPSEngine_SetSecret_OverwriteExisting(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string]string{"k": "original"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err = engine.SetSecret(encrypted, "k", "overwritten")
	if err != nil {
		t.Fatal(err)
	}

	val, err := engine.GetSecret(encrypted, "k")
	if err != nil {
		t.Fatal(err)
	}
	if val != "overwritten" {
		t.Fatalf("expected 'overwritten', got %q", val)
	}
}
