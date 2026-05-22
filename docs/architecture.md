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

- `SOPSEngine.SetSecret()` (`store/sops.go`) — decrypts to `map[string]string` in memory, updates the key, re-encrypts, returns ciphertext `[]byte`. Plaintext exists only as Go variables.
- `SOPSEngine.EncryptMap()` (`store/sops.go`) — takes a plaintext map, returns encrypted bytes. Never writes to disk.
- `GitStore.WriteFile()` (`store/git.go`) — receives already-encrypted `[]byte` from the service layer. No intermediate plaintext file is ever created.

**Any future changes must preserve this invariant.** Never introduce temporary files, debug logging of secret values, or serialization of decrypted data to disk.

## Concurrency

- **Per-namespace mutex** in service layer — serializes writes to the same SOPS file
- **Global git mutex** in GitStore — serializes all git add/commit operations (go-git requirement)
- **Lock-free reads** — decryption is stateless, reads HEAD or specific commits
