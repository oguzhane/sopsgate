package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/oergin/sopsgate/internal/api"
	"github.com/oergin/sopsgate/internal/config"
	"github.com/oergin/sopsgate/internal/service"
	"github.com/oergin/sopsgate/internal/store"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

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

	if err := http.ListenAndServe(cfg.Server.Address, router); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
