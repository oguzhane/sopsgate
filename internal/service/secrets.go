// Package service implements the business logic for sopsgate.
package service

import (
	"fmt"
	"sync"

	"github.com/oergin/sopsgate/internal/model"
	"github.com/oergin/sopsgate/internal/store"
)

// SecretsService coordinates SOPS encryption and Git storage.
type SecretsService struct {
	sops  *store.SOPSEngine
	git   *store.GitStore
	locks lockManager
}

type lockManager struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (lm *lockManager) get(namespace string) *sync.Mutex {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lm.locks == nil {
		lm.locks = make(map[string]*sync.Mutex)
	}
	l, ok := lm.locks[namespace]
	if !ok {
		l = &sync.Mutex{}
		lm.locks[namespace] = l
	}
	return l
}

// NewSecretsService creates a new service instance.
func NewSecretsService(sopsEngine *store.SOPSEngine, gitStore *store.GitStore) *SecretsService {
	return &SecretsService{
		sops: sopsEngine,
		git:  gitStore,
	}
}

// CreateNamespace creates a new namespace with an empty encrypted file.
func (s *SecretsService) CreateNamespace(namespace, author string) error {
	mu := s.locks.get(namespace)
	mu.Lock()
	defer mu.Unlock()

	if s.git.FileExists(namespace) {
		return fmt.Errorf("namespace %q already exists", namespace)
	}

	data, err := s.sops.CreateEmptyEncryptedFile()
	if err != nil {
		return fmt.Errorf("create encrypted file: %w", err)
	}

	if err := s.git.WriteFile(namespace, data); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	_, err = s.git.Commit(namespace, fmt.Sprintf("[sopsgate] CREATE namespace %s by %s", namespace, author), author)
	return err
}

// DeleteNamespace removes a namespace and all its secrets.
func (s *SecretsService) DeleteNamespace(namespace, author string) error {
	mu := s.locks.get(namespace)
	mu.Lock()
	defer mu.Unlock()

	if !s.git.FileExists(namespace) {
		return fmt.Errorf("namespace %q not found", namespace)
	}

	if err := s.git.DeleteFile(namespace); err != nil {
		return fmt.Errorf("delete file: %w", err)
	}

	_, err := s.git.CommitDelete(namespace, fmt.Sprintf("[sopsgate] DELETE namespace %s by %s", namespace, author), author)
	return err
}

// ListNamespaces returns all namespace names.
func (s *SecretsService) ListNamespaces() ([]string, error) {
	return s.git.ListNamespaces()
}

// GetSecret returns a single secret value.
func (s *SecretsService) GetSecret(namespace, key string) (*model.Secret, error) {
	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return nil, fmt.Errorf("namespace %q not found", namespace)
	}

	value, err := s.sops.GetSecret(data, key)
	if err != nil {
		return nil, err
	}

	// Get latest commit info for this namespace.
	history, err := s.git.FileHistory(namespace)
	if err != nil {
		return nil, err
	}

	secret := &model.Secret{
		Namespace: namespace,
		Key:       key,
		Value:     value,
	}
	if len(history) > 0 {
		secret.Version = history[0].Hash
		secret.UpdatedAt = history[0].Timestamp
	}

	return secret, nil
}

// ListKeys returns the key names in a namespace.
func (s *SecretsService) ListKeys(namespace string) ([]string, error) {
	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return nil, fmt.Errorf("namespace %q not found", namespace)
	}
	return s.sops.ListKeys(data)
}

// GetAllSecrets returns all key-value pairs in a namespace.
func (s *SecretsService) GetAllSecrets(namespace string) (map[string]string, error) {
	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return nil, fmt.Errorf("namespace %q not found", namespace)
	}
	return s.sops.DecryptFile(data)
}

// PutSecret creates or updates a single secret.
func (s *SecretsService) PutSecret(namespace, key, value, author string) error {
	mu := s.locks.get(namespace)
	mu.Lock()
	defer mu.Unlock()

	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return fmt.Errorf("namespace %q not found", namespace)
	}

	newData, err := s.sops.SetSecret(data, key, value)
	if err != nil {
		return fmt.Errorf("set secret: %w", err)
	}

	if err := s.git.WriteFile(namespace, newData); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	_, err = s.git.Commit(namespace, fmt.Sprintf("[sopsgate] PUT %s/%s by %s", namespace, key, author), author)
	return err
}

// BulkPutSecrets upserts multiple secrets in a namespace.
func (s *SecretsService) BulkPutSecrets(namespace string, secrets map[string]string, author string) error {
	mu := s.locks.get(namespace)
	mu.Lock()
	defer mu.Unlock()

	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return fmt.Errorf("namespace %q not found", namespace)
	}

	existing, err := s.sops.DecryptFile(data)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	for k, v := range secrets {
		existing[k] = v
	}

	newData, err := s.sops.EncryptMap(existing, data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := s.git.WriteFile(namespace, newData); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	_, err = s.git.Commit(namespace, fmt.Sprintf("[sopsgate] BULK PUT %s (%d keys) by %s", namespace, len(secrets), author), author)
	return err
}

// DeleteSecret removes a secret from a namespace.
func (s *SecretsService) DeleteSecret(namespace, key, author string) error {
	mu := s.locks.get(namespace)
	mu.Lock()
	defer mu.Unlock()

	data, err := s.git.ReadFile(namespace)
	if err != nil {
		return fmt.Errorf("namespace %q not found", namespace)
	}

	newData, err := s.sops.DeleteSecret(data, key)
	if err != nil {
		return err
	}

	if err := s.git.WriteFile(namespace, newData); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	_, err = s.git.Commit(namespace, fmt.Sprintf("[sopsgate] DELETE %s/%s by %s", namespace, key, author), author)
	return err
}

// GetVersions returns the commit history for a namespace's file.
func (s *SecretsService) GetVersions(namespace, key string) ([]model.SecretVersion, error) {
	history, err := s.git.FileHistory(namespace)
	if err != nil {
		return nil, err
	}

	versions := make([]model.SecretVersion, len(history))
	for i, h := range history {
		versions[i] = model.SecretVersion{
			Version:     h.Hash,
			CommittedAt: h.Timestamp,
			Message:     h.Message,
		}
	}
	return versions, nil
}

// GetSecretAtVersion returns a secret's value at a specific commit.
func (s *SecretsService) GetSecretAtVersion(namespace, key, version string) (*model.Secret, error) {
	// We need the full hash — try to resolve the short hash.
	fullHash, err := s.resolveHash(namespace, version)
	if err != nil {
		return nil, err
	}

	data, err := s.git.ReadFileAtCommit(namespace, fullHash)
	if err != nil {
		return nil, fmt.Errorf("read at version %s: %w", version, err)
	}

	value, err := s.sops.GetSecret(data, key)
	if err != nil {
		return nil, err
	}

	return &model.Secret{
		Namespace: namespace,
		Key:       key,
		Value:     value,
		Version:   version,
	}, nil
}

// resolveHash resolves a short hash to a full hash by scanning history.
func (s *SecretsService) resolveHash(namespace, shortHash string) (string, error) {
	history, err := s.git.FileHistory(namespace)
	if err != nil {
		return "", err
	}
	for _, h := range history {
		if h.Hash == shortHash {
			// We need the full hash — FileHistory returns short hashes.
			// Re-fetch from git log with full hashes.
			return s.git.ResolveShortHash(shortHash)
		}
	}
	return "", fmt.Errorf("version %q not found", shortHash)
}
