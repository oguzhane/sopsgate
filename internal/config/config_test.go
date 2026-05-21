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
  age_key_file: "/tmp/age.key"
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

func TestValidate_MissingAgeKeyFile(t *testing.T) {
	cfg := Config{
		Storage: StorageConfig{RepoPath: "/tmp"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for missing age_key_file")
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
