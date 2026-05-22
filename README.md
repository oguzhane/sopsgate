# SopsGate

Self-hosted secrets management service backed by [SOPS](https://github.com/getsops/sops) encryption and Git versioning. Serve your existing SOPS-encrypted secrets over a REST API with full audit trail — no database, no cloud, no vendor lock-in.

## Why SopsGate?

Most secrets managers require a database, a cluster, or a cloud account. SopsGate is different:

- **SOPS-native** — uses standard `.sops.yaml` creation rules and age keys. No proprietary formats. Bring your existing SOPS-encrypted files and serve them over HTTP without re-encryption.
- **Git as the backend** — every change is a commit. Full audit trail, versioning, and rollback built-in. No database.
- **Plaintext never touches disk** — decryption happens only in memory. Ciphertext in, ciphertext on disk, plaintext only in the HTTP response.
- **Single binary** — just Go, an age key, and a directory. No external services to run.

## Features

- **HTTP REST API** for secrets CRUD with JSON responses
- **SOPS encryption** via the Go library (not CLI) — age keys, `.sops.yaml` creation rules
- **Multiple age identities** — serve secrets encrypted with different keys from a single instance
- **Git-backed storage** — every change is a commit with author attribution
- **Secret versioning** — retrieve any historical value by commit hash
- **Namespaced secrets** — hierarchical organization (e.g., `infra/postgres`)
- **Bulk operations** — upsert multiple secrets at once
- **Pluggable auth** — Bearer tokens now, designed for mTLS/OIDC later
- **Existing SOPS compatibility** — drop in files encrypted with the `sops` CLI, serve them immediately

## Quick Start

### Prerequisites

- Go 1.25+
- [age](https://github.com/FiloSottile/age) (`brew install age` / `apt install age`)

### 1. Clone and build

```bash
git clone --recurse-submodules https://github.com/oguzhane/sopsgate.git
cd sopsgate
go build -o sopsgate ./cmd/server
```

### 2. Generate an age key

```bash
age-keygen -o sopsgate.key
```

### 3. Create a config file

```yaml
# config.yaml
server:
  address: ":8080"

storage:
  repo_path: "./secrets-repo"

auth:
  tokens:
    - name: "admin"
      token: "my-secret-token"

sops:
  age_key_files:
    - "./sopsgate.key"
```

### 4. Run

```bash
./sopsgate -config config.yaml
```

### 5. Use it

```bash
TOKEN="my-secret-token"

# Create a namespace
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/namespaces/myapp

# Store a secret
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"super-secret-123"}' \
  http://localhost:8080/api/v1/secrets/myapp/keys/db_password

# Read it back
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/secrets/myapp/keys/db_password
```

```json
{
  "namespace": "myapp",
  "key": "db_password",
  "value": "super-secret-123",
  "version": "a3f8c2d",
  "updated_at": "2026-05-22T10:30:00Z"
}
```

## Bring Your Existing SOPS Secrets

Already using SOPS? SopsGate serves your existing encrypted files directly.

1. Point `storage.repo_path` at your SOPS repo (or copy files into it)
2. Add the matching age private key(s) to `sops.age_key_files`
3. Start SopsGate — your secrets are now available over HTTP

SopsGate reads `.sops.yaml` creation rules from the repo root, so per-environment or per-directory key policies are respected automatically. See [Secrets Repo Structure](docs/secrets-repo.md) for examples.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│   Client     │────>│  HTTP Server (net/http)                      │
│  (curl/SDK)  │<────│                                              │
└─────────────┘     │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │
                    │  │  Auth    │─>│ Handlers │─>│  Service    │  │
                    │  │Middleware│  │ (API)    │  │  Layer      │  │
                    │  └─────────┘  └──────────┘  └─────┬──────┘  │
                    │                                     │         │
                    │               ┌─────────────────────┼─────┐  │
                    │               │     Store Layer      │     │  │
                    │               │  ┌──────────┐  ┌────v───┐ │  │
                    │               │  │   SOPS   │  │  Git   │ │  │
                    │               │  │ (encrypt/│  │(commit/│ │  │
                    │               │  │ decrypt) │  │history)│ │  │
                    │               │  └──────────┘  └────────┘ │  │
                    │               └───────────────────────────┘  │
                    └──────────────────────────────────────────────┘
```

**Security invariant:** Plaintext secret values never touch the filesystem. All decryption happens in memory — only SOPS-encrypted ciphertext is written to disk.

## API Overview

All endpoints require `Authorization: Bearer <token>` except `/healthz`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/healthz` | Health check |
| `GET` | `/api/v1/namespaces` | List namespaces |
| `POST` | `/api/v1/namespaces/{ns}` | Create namespace |
| `DELETE` | `/api/v1/namespaces/{ns}` | Delete namespace |
| `GET` | `/api/v1/secrets/{ns}` | List secret keys |
| `GET` | `/api/v1/secrets/{ns}?reveal=true` | Get all secrets with values |
| `PUT` | `/api/v1/secrets/{ns}` | Bulk upsert secrets |
| `GET` | `/api/v1/secrets/{ns}/keys/{key}` | Get a secret |
| `PUT` | `/api/v1/secrets/{ns}/keys/{key}` | Create/update a secret |
| `DELETE` | `/api/v1/secrets/{ns}/keys/{key}` | Delete a secret |
| `GET` | `/api/v1/secrets/{ns}/keys/{key}/versions` | Version history |
| `GET` | `/api/v1/secrets/{ns}/keys/{key}/versions/{hash}` | Secret at version |

See [API Reference](docs/api-reference.md) for request/response details.

## Testing

```bash
go test ./...                    # All tests (requires age)
go test ./e2e/ -v -count=1      # E2E tests only
```

Tests use real age keys, real SOPS encryption, and real git repos in temp directories. No mocks.

## Documentation

- [Getting Started](docs/getting-started.md) — setup and first steps
- [Configuration](docs/configuration.md) — config file reference
- [API Reference](docs/api-reference.md) — full endpoint documentation
- [Architecture](docs/architecture.md) — design and internals
- [Secrets Repo Structure](docs/secrets-repo.md) — repo layout and multi-tenant setup
- [Deployment](docs/deployment.md) — Docker, Kubernetes, production guide
