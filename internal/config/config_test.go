package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.Address != ":8080" {
		t.Errorf("expected default address :8080, got %s", cfg.Server.Address)
	}
	if cfg.Storage.RepoPath != "./data" {
		t.Errorf("expected default repo_path ./data, got %s", cfg.Storage.RepoPath)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `
server:
  address: ":9090"
storage:
  repo_path: "/tmp/secrets"
  auto_push: true
auth:
  tokens:
    - name: admin
      token: "sk-test-123"
sops:
  age_key_files:
    - "/tmp/age.key"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Address != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.Server.Address)
	}
	if cfg.Storage.RepoPath != "/tmp/secrets" {
		t.Errorf("expected /tmp/secrets, got %s", cfg.Storage.RepoPath)
	}
	if !cfg.Storage.AutoPush {
		t.Error("expected auto_push true")
	}
	if len(cfg.Auth.Tokens) != 1 || cfg.Auth.Tokens[0].Name != "admin" {
		t.Errorf("expected 1 token named admin, got %+v", cfg.Auth.Tokens)
	}
}

func TestValidate_MissingRepoPath(t *testing.T) {
	cfg := Config{}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for missing repo_path")
	}
}

func TestValidate_MissingAgeKeyFiles(t *testing.T) {
	// Unset env var to ensure validation catches missing keys.
	orig := os.Getenv("SOPS_AGE_KEY_FILE")
	os.Unsetenv("SOPS_AGE_KEY_FILE")
	defer os.Setenv("SOPS_AGE_KEY_FILE", orig)

	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for missing age_key_files")
	}
}

func TestValidate_EnvVarFallback(t *testing.T) {
	os.Setenv("SOPS_AGE_KEY_FILE", "/tmp/env-key.key")
	defer os.Unsetenv("SOPS_AGE_KEY_FILE")

	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error when SOPS_AGE_KEY_FILE is set, got: %v", err)
	}

	files := cfg.ResolveAgeKeyFiles()
	if len(files) != 1 || files[0] != "/tmp/env-key.key" {
		t.Errorf("expected [/tmp/env-key.key], got %v", files)
	}
}

func TestResolveAgeKeyFiles_MergesConfigAndEnv(t *testing.T) {
	os.Setenv("SOPS_AGE_KEY_FILE", "/tmp/env-key.key")
	defer os.Unsetenv("SOPS_AGE_KEY_FILE")

	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/config-key.key"}},
	}
	files := cfg.ResolveAgeKeyFiles()
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %v", files)
	}
	if files[0] != "/tmp/config-key.key" || files[1] != "/tmp/env-key.key" {
		t.Errorf("unexpected files: %v", files)
	}
}

func TestResolveAgeKeyFiles_DeduplicatesEnv(t *testing.T) {
	os.Setenv("SOPS_AGE_KEY_FILE", "/tmp/same.key")
	defer os.Unsetenv("SOPS_AGE_KEY_FILE")

	cfg := Config{
		SOPS: SOPSConfig{AgeKeyFiles: []string{"/tmp/same.key"}},
	}
	files := cfg.ResolveAgeKeyFiles()
	if len(files) != 1 {
		t.Errorf("expected deduplication, got %v", files)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	os.WriteFile(cfgPath, []byte("{{invalid"), 0644)

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidate_TLS_CertWithoutKey(t *testing.T) {
	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/k.key"}},
		Server:  ServerConfig{Address: ":8080", TLS: TLSConfig{CertFile: "/tmp/cert.pem"}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for cert_file without key_file")
	}
}

func TestValidate_TLS_KeyWithoutCert(t *testing.T) {
	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/k.key"}},
		Server:  ServerConfig{Address: ":8080", TLS: TLSConfig{KeyFile: "/tmp/key.pem"}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for key_file without cert_file")
	}
}

func TestValidate_TLS_ClientCAWithoutServerCert(t *testing.T) {
	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/k.key"}},
		Server:  ServerConfig{Address: ":8080", TLS: TLSConfig{ClientCAFile: "/tmp/ca.pem"}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for client_ca_file without server cert")
	}
}

func TestValidate_TLS_NonexistentFiles(t *testing.T) {
	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/k.key"}},
		Server: ServerConfig{Address: ":8080", TLS: TLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for nonexistent TLS files")
	}
}

func TestValidate_TLS_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(certFile, []byte("cert"), 0644)
	os.WriteFile(keyFile, []byte("key"), 0644)
	os.WriteFile(caFile, []byte("ca"), 0644)

	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
		SOPS:    SOPSConfig{AgeKeyFiles: []string{"/tmp/k.key"}},
		Server: ServerConfig{Address: ":8443", TLS: TLSConfig{
			CertFile:     certFile,
			KeyFile:      keyFile,
			ClientCAFile: caFile,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid TLS config, got: %v", err)
	}
	if !cfg.Server.TLS.Enabled() {
		t.Fatal("expected TLS enabled")
	}
	if !cfg.Server.TLS.MutualTLS() {
		t.Fatal("expected mTLS enabled")
	}
}

func TestTLSConfig_Enabled(t *testing.T) {
	if (TLSConfig{}).Enabled() {
		t.Fatal("empty config should not be enabled")
	}
	if (TLSConfig{CertFile: "a"}).Enabled() {
		t.Fatal("cert without key should not be enabled")
	}
	if !(TLSConfig{CertFile: "a", KeyFile: "b"}).Enabled() {
		t.Fatal("cert + key should be enabled")
	}
}

func TestTLSConfig_MutualTLS(t *testing.T) {
	if (TLSConfig{CertFile: "a", KeyFile: "b"}).MutualTLS() {
		t.Fatal("no client CA should not be mTLS")
	}
	if !(TLSConfig{CertFile: "a", KeyFile: "b", ClientCAFile: "c"}).MutualTLS() {
		t.Fatal("all three fields should be mTLS")
	}
}
