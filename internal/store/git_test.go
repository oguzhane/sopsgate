package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGitStore_InitAndFileOps(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ns := "test/myapp"

	// File should not exist yet.
	if gs.FileExists(ns) {
		t.Fatal("file should not exist")
	}

	// Write a file.
	if err := gs.WriteFile(ns, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !gs.FileExists(ns) {
		t.Fatal("file should exist")
	}

	// Read back.
	data, err := gs.ReadFile(ns)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}

	// Commit.
	hash, err := gs.Commit(ns, "test commit", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 7 {
		t.Fatalf("expected 7-char hash, got %q", hash)
	}

	// History.
	history, err := gs.FileHistory(ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(history))
	}
	if history[0].Message != "test commit" {
		t.Fatalf("expected 'test commit', got %q", history[0].Message)
	}

	// Update and commit again.
	if err := gs.WriteFile(ns, []byte("world")); err != nil {
		t.Fatal(err)
	}
	_, err = gs.Commit(ns, "second commit", "tester")
	if err != nil {
		t.Fatal(err)
	}

	history, err = gs.FileHistory(ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(history))
	}

	// Read at first commit.
	fullHash, err := gs.ResolveShortHash(history[1].Hash)
	if err != nil {
		t.Fatal(err)
	}
	data, err = gs.ReadFileAtCommit(ns, fullHash)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello' at first commit, got %q", string(data))
	}
}

func TestGitStore_ListNamespaces(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Initially empty.
	nss, err := gs.ListNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(nss) != 0 {
		t.Fatalf("expected 0 namespaces, got %d", len(nss))
	}

	// Create some files.
	gs.WriteFile("infra/postgres", []byte("data1"))
	gs.WriteFile("apps/myapp", []byte("data2"))

	nss, err = gs.ListNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(nss) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(nss))
	}
}

func TestGitStore_DeleteFile(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ns := "test/del"
	gs.WriteFile(ns, []byte("data"))
	gs.Commit(ns, "add", "tester")

	if err := gs.DeleteFile(ns); err != nil {
		t.Fatal(err)
	}
	if gs.FileExists(ns) {
		t.Fatal("file should be deleted")
	}
}

func TestGitStore_CommitDelete(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ns := "test/commitdel"
	gs.WriteFile(ns, []byte("data"))
	gs.Commit(ns, "add", "tester")

	gs.DeleteFile(ns)
	hash, err := gs.CommitDelete(ns, "remove file", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 7 {
		t.Fatalf("expected 7-char hash, got %q", hash)
	}
}

func TestGitStore_RepoPath(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gs.RepoPath() != dir {
		t.Fatalf("expected %s, got %s", dir, gs.RepoPath())
	}
}

func TestGitStore_SecretFilePath(t *testing.T) {
	dir := t.TempDir()
	gs, _ := NewGitStore(dir)
	expected := filepath.Join(dir, "secrets", "infra/postgres.sops.yaml")
	got := gs.SecretFilePath("infra/postgres")
	if got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestGitStore_OpenExisting(t *testing.T) {
	dir := t.TempDir()

	// Init first.
	gs1, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	gs1.WriteFile("test/ns", []byte("data"))
	gs1.Commit("test/ns", "init", "tester")

	// Re-open.
	gs2, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := gs2.ReadFile("test/ns")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Fatalf("expected 'data', got %q", data)
	}
}

func TestGitStore_InvalidDir(t *testing.T) {
	// Using a file as repo path should fail or init will handle it.
	tmp := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(tmp, []byte("not a dir"), 0644)
	_, err := NewGitStore(tmp)
	if err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestGitStore_ConcurrentCommits(t *testing.T) {
	dir := t.TempDir()
	gs, err := NewGitStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Write initial files for multiple namespaces
	for i := range 5 {
		ns := fmt.Sprintf("ns%d", i)
		gs.WriteFile(ns, []byte(fmt.Sprintf("initial-%d", i)))
		gs.Commit(ns, fmt.Sprintf("init %s", ns), "tester")
	}

	// Concurrent commits to different namespaces
	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := range 5 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ns := fmt.Sprintf("ns%d", i)
			for j := range 5 {
				gs.WriteFile(ns, []byte(fmt.Sprintf("data-%d-%d", i, j)))
				_, err := gs.Commit(ns, fmt.Sprintf("update %s round %d", ns, j), "tester")
				if err != nil {
					errs <- fmt.Errorf("ns%d round %d: %w", i, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify each namespace has the expected history length
	for i := range 5 {
		ns := fmt.Sprintf("ns%d", i)
		history, err := gs.FileHistory(ns)
		if err != nil {
			t.Errorf("ns%d history: %v", i, err)
			continue
		}
		// 1 init + 5 updates = 6 commits per namespace
		if len(history) != 6 {
			t.Errorf("ns%d: expected 6 commits, got %d", i, len(history))
		}
	}
}
