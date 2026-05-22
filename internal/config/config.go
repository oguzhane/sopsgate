// Package config handles loading and validating sopsgate configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for sopsgate.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Storage StorageConfig `yaml:"storage"`
	Auth    AuthConfig    `yaml:"auth"`
	SOPS    SOPSConfig    `yaml:"sops"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Address string    `yaml:"address"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig holds TLS and mutual TLS settings.
type TLSConfig struct {
	CertFile     string `yaml:"cert_file"`      // Server certificate path
	KeyFile      string `yaml:"key_file"`        // Server private key path
	ClientCAFile string `yaml:"client_ca_file"`  // CA certificate for client verification (enables mTLS)
}

// Enabled returns true if server TLS is configured (cert + key).
func (t TLSConfig) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// MutualTLS returns true if mutual TLS is configured (TLS + client CA).
func (t TLSConfig) MutualTLS() bool { return t.Enabled() && t.ClientCAFile != "" }

// StorageConfig holds git-backed storage settings.
type StorageConfig struct {
	RepoPath string `yaml:"repo_path"`
	Remote   string `yaml:"remote_url"`
	AutoPush bool   `yaml:"auto_push"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Tokens []TokenConfig `yaml:"tokens"`
}

// TokenConfig defines a static API token.
type TokenConfig struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
}

// SOPSConfig holds SOPS-related settings.
type SOPSConfig struct {
	AgeKeyFiles []string `yaml:"age_key_files"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Address: ":8080",
		},
		Storage: StorageConfig{
			RepoPath: "./data",
		},
	}
}

// Load reads a YAML config file and returns a Config.
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// Validate checks that required fields are set.
func (c Config) Validate() error {
	if c.Storage.RepoPath == "" {
		return fmt.Errorf("storage.repo_path is required")
	}
	if len(c.SOPS.AgeKeyFiles) == 0 && os.Getenv("SOPS_AGE_KEY_FILE") == "" {
		return fmt.Errorf("sops.age_key_files or SOPS_AGE_KEY_FILE env var is required")
	}

	// TLS validation.
	tls := c.Server.TLS
	if (tls.CertFile != "") != (tls.KeyFile != "") {
		return fmt.Errorf("server.tls: both cert_file and key_file are required together")
	}
	if tls.ClientCAFile != "" && !tls.Enabled() {
		return fmt.Errorf("server.tls: client_ca_file requires cert_file and key_file")
	}
	for _, pair := range []struct{ name, path string }{
		{"cert_file", tls.CertFile},
		{"key_file", tls.KeyFile},
		{"client_ca_file", tls.ClientCAFile},
	} {
		if pair.path != "" {
			if _, err := os.Stat(pair.path); err != nil {
				return fmt.Errorf("server.tls.%s: %w", pair.name, err)
			}
		}
	}

	return nil
}

// ResolveAgeKeyFiles returns the effective list of age key file paths,
// merging config and SOPS_AGE_KEY_FILE env var.
func (c Config) ResolveAgeKeyFiles() []string {
	files := make([]string, 0, len(c.SOPS.AgeKeyFiles)+1)
	files = append(files, c.SOPS.AgeKeyFiles...)
	if envFile := os.Getenv("SOPS_AGE_KEY_FILE"); envFile != "" {
		// Avoid duplicates.
		for _, f := range files {
			if f == envFile {
				return files
			}
		}
		files = append(files, envFile)
	}
	return files
}
