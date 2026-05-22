// Package store provides the SOPS encryption/decryption engine.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	sopsconfig "github.com/getsops/sops/v3/config"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
)

// SOPSEngine handles encryption and decryption of secret files using the SOPS library.
type SOPSEngine struct {
	ageKeyFiles []string
	identities  age.ParsedIdentities
	recipients  []string
	store       *yamlstore.Store
	cipher      sops.Cipher
	repoPath    string
	mu          sync.Mutex
}

// NewSOPSEngine creates a new SOPS engine with age key support.
// Accepts multiple key file paths; all identities and recipients are merged.
func NewSOPSEngine(ageKeyFiles []string) (*SOPSEngine, error) {
	var allIdentities age.ParsedIdentities
	var allRecipients []string

	for _, keyFile := range ageKeyFiles {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read age key file %s: %w", keyFile, err)
		}

		var identities age.ParsedIdentities
		if err := identities.Import(string(data)); err != nil {
			return nil, fmt.Errorf("parse age identities from %s: %w", keyFile, err)
		}
		allIdentities = append(allIdentities, identities...)

		recipients, err := parseAgeRecipients(data)
		if err != nil {
			return nil, fmt.Errorf("parse age recipients from %s: %w", keyFile, err)
		}
		allRecipients = append(allRecipients, recipients...)
	}

	if len(allIdentities) == 0 {
		return nil, fmt.Errorf("no age identities found in key files")
	}

	// Set SOPS_AGE_KEY_FILE for the SOPS keyservice which reads it internally.
	// When multiple key files are provided, set to the first one — the keyservice
	// only needs one path, and our applyIdentities handles the rest.
	if len(ageKeyFiles) > 0 {
		os.Setenv("SOPS_AGE_KEY_FILE", ageKeyFiles[0])
	}

	return &SOPSEngine{
		ageKeyFiles: ageKeyFiles,
		identities:  allIdentities,
		recipients:  allRecipients,
		store:       yamlstore.NewStore(&sopsconfig.YAMLStoreConfig{Indent: 4}),
		cipher:      aes.NewCipher(),
	}, nil
}

// SetRepoPath sets the secrets repo path, used to locate .sops.yaml.
func (e *SOPSEngine) SetRepoPath(path string) {
	e.repoPath = path
}

// KeyGroupsForFile resolves the SOPS key groups for a namespace by reading
// .sops.yaml creation rules from the repo root. Returns nil if no .sops.yaml
// exists (callers should fall back to engine defaults).
func (e *SOPSEngine) KeyGroupsForFile(namespace string) ([]sops.KeyGroup, error) {
	if e.repoPath == "" {
		return nil, nil
	}

	confPath := filepath.Join(e.repoPath, ".sops.yaml")
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return nil, nil
	}

	filePath := filepath.Join(e.repoPath, "secrets", namespace+".sops.yaml")

	cfg, err := sopsconfig.LoadCreationRuleForFile(confPath, filePath, nil)
	if err != nil {
		return nil, fmt.Errorf("load creation rule for %s: %w", namespace, err)
	}

	return cfg.KeyGroups, nil
}

// parseAgeRecipients extracts public key recipients from an age key file.
func parseAgeRecipients(data []byte) ([]string, error) {
	var recipients []string
	const prefix = "# public key: "
	for _, line := range splitLines(data) {
		if len(line) > len(prefix) && line[:len(prefix)] == prefix {
			recipients = append(recipients, line[len(prefix):])
		}
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no age public key found in key file")
	}
	return recipients, nil
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// applyIdentities applies age identities to all age master keys in the tree.
func (e *SOPSEngine) applyIdentities(tree *sops.Tree) {
	for _, kg := range tree.Metadata.KeyGroups {
		for _, mk := range kg {
			if ageMK, ok := mk.(*age.MasterKey); ok {
				e.identities.ApplyToMasterKey(ageMK)
			}
		}
	}
}

// DecryptFile decrypts a SOPS-encrypted YAML file and returns key-value pairs.
func (e *SOPSEngine) DecryptFile(encrypted []byte) (map[string]string, error) {
	tree, err := e.store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("load encrypted file: %w", err)
	}

	e.applyIdentities(&tree)

	dataKey, err := tree.Metadata.GetDataKey()
	if err != nil {
		return nil, fmt.Errorf("get data key: %w", err)
	}

	if _, err := tree.Decrypt(dataKey, e.cipher); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return treeToMap(tree.Branches), nil
}

// EncryptMap encrypts key-value pairs into a SOPS-encrypted YAML file.
// If existingEncrypted is non-nil, it updates the existing file (preserving metadata).
// Otherwise creates a new encrypted file using the provided keyGroups.
// If keyGroups is nil for a new file, falls back to the engine's own age recipients.
func (e *SOPSEngine) EncryptMap(secrets map[string]string, existingEncrypted []byte, keyGroups []sops.KeyGroup) ([]byte, error) {
	var tree sops.Tree

	if existingEncrypted != nil {
		var err error
		tree, err = e.store.LoadEncryptedFile(existingEncrypted)
		if err != nil {
			return nil, fmt.Errorf("load existing: %w", err)
		}

		e.applyIdentities(&tree)

		dataKey, err := tree.Metadata.GetDataKey()
		if err != nil {
			return nil, fmt.Errorf("get data key: %w", err)
		}

		if _, err := tree.Decrypt(dataKey, e.cipher); err != nil {
			return nil, fmt.Errorf("decrypt for update: %w", err)
		}

		tree.Branches = mapToTreeBranches(secrets)

		mac, err := tree.Encrypt(dataKey, e.cipher)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		tree.Metadata.MessageAuthenticationCode = mac
	} else {
		groups := keyGroups
		if len(groups) == 0 {
			groups = []sops.KeyGroup{e.newAgeMasterKeys()}
		}

		tree = sops.Tree{
			Branches: mapToTreeBranches(secrets),
			Metadata: sops.Metadata{
				KeyGroups:         groups,
				Version:           "3.9.0",
				UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			},
		}

		dataKey, errs := tree.GenerateDataKey()
		if len(errs) > 0 {
			return nil, fmt.Errorf("generate data key: %v", errs)
		}

		mac, err := tree.Encrypt(dataKey, e.cipher)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		tree.Metadata.MessageAuthenticationCode = mac
	}

	out, err := e.store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("emit encrypted file: %w", err)
	}

	return out, nil
}

// newAgeMasterKeys creates a KeyGroup with the configured age recipients.
func (e *SOPSEngine) newAgeMasterKeys() sops.KeyGroup {
	var kg sops.KeyGroup
	for _, r := range e.recipients {
		mk, err := age.MasterKeyFromRecipient(r)
		if err != nil {
			continue
		}
		kg = append(kg, mk)
	}
	return kg
}

// treeToMap converts SOPS TreeBranches to a flat string map.
func treeToMap(branches sops.TreeBranches) map[string]string {
	result := make(map[string]string)
	for _, branch := range branches {
		for _, item := range branch {
			key, ok := item.Key.(string)
			if !ok {
				continue
			}
			result[key] = fmt.Sprintf("%v", item.Value)
		}
	}
	return result
}

// mapToTreeBranches converts a string map to SOPS TreeBranches.
func mapToTreeBranches(secrets map[string]string) sops.TreeBranches {
	var branch sops.TreeBranch
	keys := sortedKeys(secrets)
	for _, k := range keys {
		branch = append(branch, sops.TreeItem{
			Key:   k,
			Value: secrets[k],
		})
	}
	return sops.TreeBranches{branch}
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

// CreateEmptyEncryptedFile creates a new encrypted YAML file with no secrets.
// keyGroups determines which recipients to use; nil falls back to engine defaults.
func (e *SOPSEngine) CreateEmptyEncryptedFile(keyGroups []sops.KeyGroup) ([]byte, error) {
	return e.EncryptMap(map[string]string{}, nil, keyGroups)
}

// SetSecret decrypts an existing file, sets/updates a key, and re-encrypts.
func (e *SOPSEngine) SetSecret(encrypted []byte, key, value string) ([]byte, error) {
	secrets, err := e.DecryptFile(encrypted)
	if err != nil {
		return nil, err
	}
	secrets[key] = value
	return e.EncryptMap(secrets, encrypted, nil)
}

// DeleteSecret decrypts an existing file, removes a key, and re-encrypts.
func (e *SOPSEngine) DeleteSecret(encrypted []byte, key string) ([]byte, error) {
	secrets, err := e.DecryptFile(encrypted)
	if err != nil {
		return nil, err
	}
	if _, exists := secrets[key]; !exists {
		return nil, fmt.Errorf("key %q not found", key)
	}
	delete(secrets, key)
	return e.EncryptMap(secrets, encrypted, nil)
}

// GetSecret decrypts and returns a single secret value.
func (e *SOPSEngine) GetSecret(encrypted []byte, key string) (string, error) {
	secrets, err := e.DecryptFile(encrypted)
	if err != nil {
		return "", err
	}
	v, ok := secrets[key]
	if !ok {
		return "", fmt.Errorf("key %q not found", key)
	}
	return v, nil
}

// ListKeys decrypts and returns just the key names.
func (e *SOPSEngine) ListKeys(encrypted []byte) ([]string, error) {
	secrets, err := e.DecryptFile(encrypted)
	if err != nil {
		return nil, err
	}
	return sortedKeys(secrets), nil
}
