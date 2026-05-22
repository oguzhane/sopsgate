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
