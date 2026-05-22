# SopsGate — Architecture

## Overview

SopsGate is a self-hosted HTTP secrets management service backed by SOPS encryption and Git versioning. Think Azure Key Vault, but running in your homelab with SOPS-encrypted files in a git repo.

## System Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│   Client     │────▶│  HTTP Server (net/http)                      │
│  (curl/SDK)  │◀────│                                              │
└─────────────┘     │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
                    │  │  Auth    │─▶│ Handlers │─▶│  Service    │  │
                    │  │Middleware│  │ (API)    │  │  Layer      │  │
                    │  └─────────┘  └──────────┘  └─────┬──────┘  │
                    │                                     │         │
                    │               ┌─────────────────────┼─────┐  │
                    │               │     Store Layer      │     │  │
                    │               │  ┌──────────┐  ┌────▼───┐ │  │
                    │               │  │   SOPS   │  │  Git   │ │  │
                    │               │  │ (encrypt/│  │(commit/│ │  │
                    │               │  │ decrypt) │  │history)│ │  │
                    │               │  └──────────┘  └────────┘ │  │
                    │               └───────────────────────────┘  │
                    └──────────────────────────────────────────────┘
```

## Layers

### HTTP Layer (`internal/api/`)
- Standard library `net/http` with `ServeMux`
- Catch-all routing with manual path parsing (supports slashed namespaces like `infra/postgres`)
- JSON request/response serialization

### Auth Middleware (`internal/api/middleware.go`)
- Pluggable `Authenticator` interface
- V1: Static bearer token auth (`TokenAuth`)
- Designed for future mTLS, OIDC, or path-based ACL extensions

### Service Layer (`internal/service/`)
- Business logic coordinating SOPS and Git operations
- Per-namespace mutex for write serialization
- Namespace CRUD, secret CRUD, versioning, bulk operations

### Store Layer (`internal/store/`)
- **SOPSEngine** — Wraps the SOPS Go library (imported as git submodule). Handles encryption/decryption using age keys. Uses `sops.Tree` and `stores/yaml.Store` for YAML handling.
- **GitStore** — Wraps go-git. Manages file I/O, commits, history, and file-at-commit retrieval. Global mutex protects git index operations.

## Data Model

Each namespace maps to a single SOPS-encrypted YAML file:

```
secrets-repo/
  secrets/
    myapp.sops.yaml              # namespace: myapp
    infra/
      postgres.sops.yaml         # namespace: infra/postgres
```

## Write Flow

1. Service acquires per-namespace lock
2. SOPSEngine reads + decrypts the file
3. In-memory modification (set/delete key)
4. SOPSEngine re-encrypts with same data key
5. GitStore writes to disk
6. GitStore commits (global git lock)
7. Release namespace lock

## Security Invariant: No Plaintext on Disk

**Plaintext secret values must NEVER be written to disk.** This is a non-negotiable constraint.

All decryption happens in memory. The only data written to the filesystem is SOPS-encrypted ciphertext. The flow is:

```
disk (ciphertext) → memory (decrypt) → memory (mutate) → memory (re-encrypt) → disk (ciphertext)
```

Key code enforcing this:

- `SOPSEngine.SetSecret()` (`store/sops.go`) — decrypts to `map[string][]byte` in memory, updates the key, re-encrypts, returns ciphertext `[]byte`. Plaintext exists only as Go variables.
- `SOPSEngine.EncryptMap()` (`store/sops.go`) — takes a plaintext map, returns encrypted bytes. Never writes to disk.
- `GitStore.WriteFile()` (`store/git.go`) — receives already-encrypted `[]byte` from the service layer. No intermediate plaintext file is ever created.

**Any future changes must preserve this invariant.** Never introduce temporary files, debug logging of secret values, or serialization of decrypted data to disk.

### Memory Zeroing

Plaintext secret values are stored as `[]byte` (not Go `string`) throughout the internal data path. This allows deterministic zeroing of memory after use — defense against memory dump attacks (cold boot, hypervisor inspection, `/proc/pid/mem`).

- `ZeroBytes(b []byte)` — overwrites every byte with zero
- `ZeroSecretMap(m map[string][]byte)` — zeros all value slices and clears the map

Every function that decrypts secrets uses `defer ZeroSecretMap(secrets)` or `defer ZeroBytes(dataKey)` to clean up. String conversion (`string([]byte)`) happens only at the HTTP response boundary in the handler/service layer, keeping the plaintext window as short as possible.

## Concurrency

- **Per-namespace mutex** in service layer — serializes writes to the same SOPS file
- **Global git mutex** in GitStore — serializes all git add/commit operations (go-git requirement)
- **Lock-free reads** — decryption is stateless, reads HEAD or specific commits

## Identity Management

SopsGate follows standard SOPS conventions for key management — it does not introduce its own identity configuration format.

### Decryption (age identities)

`SOPSEngine` loads age private keys from multiple key files (configured via `sops.age_key_files` or `SOPS_AGE_KEY_FILE` env var). All identities are merged into a single pool. When decrypting, SOPS matches the correct identity against the encrypted file's metadata automatically.

This enables multi-tenant setups: files encrypted with different age keys can coexist in the same repo, and SopsGate decrypts each using the matching identity.

### Encryption (`.sops.yaml` creation rules)

When creating new namespaces, SopsGate reads `.sops.yaml` from the secrets repo root and uses SOPS's `LoadCreationRuleForFile()` to resolve which recipients (age public keys) to use. Rules are matched by `path_regex` against the namespace file path (`secrets/{namespace}.sops.yaml`).

If no `.sops.yaml` exists, SopsGate falls back to the recipients extracted from the configured age key files.

When updating existing secrets, the recipients are already embedded in the SOPS metadata — no rule resolution is needed.

