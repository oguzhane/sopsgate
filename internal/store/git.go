// Package store provides the git-backed storage layer.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitStore manages a git repository for secret storage and versioning.
type GitStore struct {
	repoPath string
	repo     *git.Repository
	mu       sync.Mutex // protects all git operations (add/commit)
}

// NewGitStore opens or initializes a git repo at the given path.
func NewGitStore(repoPath string) (*GitStore, error) {
	if err := os.MkdirAll(repoPath, 0750); err != nil {
		return nil, fmt.Errorf("create repo dir: %w", err)
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		repo, err = git.PlainInit(repoPath, false)
		if err != nil {
			return nil, fmt.Errorf("init git repo: %w", err)
		}
	}

	return &GitStore{repoPath: repoPath, repo: repo}, nil
}

// SecretFilePath returns the filesystem path for a namespace's SOPS file.
func (g *GitStore) SecretFilePath(namespace string) string {
	return filepath.Join(g.repoPath, "secrets", namespace+".sops.yaml")
}

// relPath returns the path relative to the repo root.
func (g *GitStore) relPath(namespace string) string {
	return filepath.Join("secrets", namespace+".sops.yaml")
}

// ReadFile reads the current content of a namespace's secrets file.
func (g *GitStore) ReadFile(namespace string) ([]byte, error) {
	return os.ReadFile(g.SecretFilePath(namespace))
}

// WriteFile writes content to a namespace's secrets file (does not commit).
func (g *GitStore) WriteFile(namespace string, data []byte) error {
	path := g.SecretFilePath(namespace)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// DeleteFile removes a namespace's secrets file (does not commit).
func (g *GitStore) DeleteFile(namespace string) error {
	return os.Remove(g.SecretFilePath(namespace))
}

// FileExists checks if a namespace's secrets file exists.
func (g *GitStore) FileExists(namespace string) bool {
	_, err := os.Stat(g.SecretFilePath(namespace))
	return err == nil
}

// Commit stages a file and commits with the given message.
func (g *GitStore) Commit(namespace, message, author string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	wt, err := g.repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}

	rel := g.relPath(namespace)
	if _, err := wt.Add(rel); err != nil {
		return "", fmt.Errorf("git add %s: %w", rel, err)
	}

	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author,
			Email: author + "@sopsgate",
			When:  time.Now(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	return hash.String()[:7], nil
}

// CommitDelete stages the removal of a file and commits.
func (g *GitStore) CommitDelete(namespace, message, author string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	wt, err := g.repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}

	rel := g.relPath(namespace)
	if _, err := wt.Remove(rel); err != nil {
		return "", fmt.Errorf("git rm %s: %w", rel, err)
	}

	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author,
			Email: author + "@sopsgate",
			When:  time.Now(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	return hash.String()[:7], nil
}

// CommitInfo holds metadata about a git commit.
type CommitInfo struct {
	Hash      string
	Message   string
	Timestamp time.Time
}

// FileHistory returns the commit history for a namespace's file.
func (g *GitStore) FileHistory(namespace string) ([]CommitInfo, error) {
	ref, err := g.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("get HEAD: %w", err)
	}

	rel := g.relPath(namespace)
	iter, err := g.repo.Log(&git.LogOptions{
		From:     ref.Hash(),
		FileName: &rel,
	})
	if err != nil {
		return nil, fmt.Errorf("git log: %w", err)
	}

	var history []CommitInfo
	err = iter.ForEach(func(c *object.Commit) error {
		history = append(history, CommitInfo{
			Hash:      c.Hash.String()[:7],
			Message:   strings.TrimSpace(c.Message),
			Timestamp: c.Author.When,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("iterate log: %w", err)
	}

	return history, nil
}

// ReadFileAtCommit reads a file's content at a specific commit hash.
func (g *GitStore) ReadFileAtCommit(namespace, commitHash string) ([]byte, error) {
	hash := plumbing.NewHash(commitHash)
	commit, err := g.repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("get commit %s: %w", commitHash, err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("get tree: %w", err)
	}

	rel := g.relPath(namespace)
	file, err := tree.File(rel)
	if err != nil {
		return nil, fmt.Errorf("get file %s at %s: %w", rel, commitHash, err)
	}

	contents, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return []byte(contents), nil
}

// ListNamespaces scans the secrets/ directory and returns all namespace names.
func (g *GitStore) ListNamespaces() ([]string, error) {
	secretsDir := filepath.Join(g.repoPath, "secrets")
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	var namespaces []string
	err := filepath.Walk(secretsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".sops.yaml") {
			return nil
		}

		rel, err := filepath.Rel(secretsDir, path)
		if err != nil {
			return err
		}
		// Remove .sops.yaml suffix to get namespace name.
		ns := strings.TrimSuffix(rel, ".sops.yaml")
		namespaces = append(namespaces, ns)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk secrets dir: %w", err)
	}

	return namespaces, nil
}

// RepoPath returns the repository path.
func (g *GitStore) RepoPath() string {
	return g.repoPath
}

// ResolveShortHash resolves a short commit hash to the full hash.
func (g *GitStore) ResolveShortHash(short string) (string, error) {
	ref, err := g.repo.Head()
	if err != nil {
		return "", fmt.Errorf("get HEAD: %w", err)
	}

	iter, err := g.repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return "", fmt.Errorf("git log: %w", err)
	}

	var fullHash string
	err = iter.ForEach(func(c *object.Commit) error {
		if c.Hash.String()[:len(short)] == short {
			fullHash = c.Hash.String()
			return fmt.Errorf("found") // stop iteration
		}
		return nil
	})
	if fullHash != "" {
		return fullHash, nil
	}
	if err != nil && err.Error() != "found" {
		return "", err
	}
	return "", fmt.Errorf("commit %q not found", short)
}
