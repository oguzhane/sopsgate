package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/oguzhane/sopsgate/internal/api"
	"github.com/oguzhane/sopsgate/internal/config"
	"github.com/oguzhane/sopsgate/internal/service"
	"github.com/oguzhane/sopsgate/internal/store"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Apply plugin environment (PATH, env vars) before SOPS init.
	cfg.ApplyPluginEnv()

	// Initialize SOPS engine.
	ageKeyFiles := cfg.ResolveAgeKeyFiles()
	sopsEngine, err := store.NewSOPSEngine(ageKeyFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing SOPS: %v\n", err)
		os.Exit(1)
	}

	// Initialize Git store.
	gitStore, err := store.NewGitStore(cfg.Storage.RepoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing Git store: %v\n", err)
		os.Exit(1)
	}

	// Wire repo path so SOPSEngine can find .sops.yaml.
	sopsEngine.SetRepoPath(gitStore.RepoPath())

	// Initialize service.
	svc := service.NewSecretsService(sopsEngine, gitStore)

	// Initialize HTTP handler.
	handler := api.NewHandler(svc)

	// Set up auth.
	var auth api.Authenticator
	if len(cfg.Auth.Tokens) > 0 {
		tokens := make([]struct{ Name, Token string }, len(cfg.Auth.Tokens))
		for i, t := range cfg.Auth.Tokens {
			tokens[i] = struct{ Name, Token string }{Name: t.Name, Token: t.Token}
		}
		auth = api.NewTokenAuth(tokens)
	}

	router := api.NewRouter(handler, auth)

	log.Printf("sopsgate starting on %s", cfg.Server.Address)
	log.Printf("secrets repo: %s", cfg.Storage.RepoPath)

	if cfg.Server.TLS.MutualTLS() {
		tlsCfg, err := buildMutualTLSConfig(cfg.Server.TLS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TLS config error: %v\n", err)
			os.Exit(1)
		}
		srv := &http.Server{
			Addr:      cfg.Server.Address,
			Handler:   router,
			TLSConfig: tlsCfg,
		}
		log.Printf("mTLS enabled (client CA: %s)", cfg.Server.TLS.ClientCAFile)
		if err := srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	} else if cfg.Server.TLS.Enabled() {
		log.Printf("TLS enabled")
		if err := http.ListenAndServeTLS(cfg.Server.Address, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile, router); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := http.ListenAndServe(cfg.Server.Address, router); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}
}

// buildMutualTLSConfig creates a tls.Config that requires and verifies client certificates.
func buildMutualTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	caCert, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse client CA certificate")
	}

	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}
