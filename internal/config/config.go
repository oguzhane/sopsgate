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
	Address string `yaml:"address"`
}

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
	AgeKeyFile string `yaml:"age_key_file"`
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
	if c.SOPS.AgeKeyFile == "" {
		return fmt.Errorf("sops.age_key_file is required")
	}
	return nil
}
