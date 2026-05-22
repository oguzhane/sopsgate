# SopsGate

Self-hosted secrets management service backed by [SOPS](https://github.com/getsops/sops) encryption and Git versioning.

Like Azure Key Vault or HashiCorp Vault, but running in your homelab with age-encrypted YAML files in a git repo.

## Features

- **HTTP REST API** for secrets CRUD
- **SOPS encryption** via the Go library (not CLI) — age, PGP, cloud KMS
- **Git-backed storage** — every change is a commit with full audit trail
- **Secret versioning** — retrieve any historical value via git history
- **Namespaced secrets** — hierarchical organization (e.g., `infra/postgres`)
- **Bulk operations** — upsert multiple secrets at once
- **Pluggable auth** — Bearer tokens now, designed for mTLS/OIDC later
- **Zero external dependencies** — just Go, git, and an age key

## Quick Start

```bash
# Generate an age key
age-keygen -o sopsgate.key

# Create config.yaml (see docs/configuration.md)

# Build & run
git clone --recurse-submodules <repo-url>
cd sopsgate
go build -o sopsgate ./cmd/server
./sopsgate -config config.yaml

# Store a secret
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/namespaces/myapp
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -d '{"value":"secret"}' http://localhost:8080/api/v1/secrets/myapp/keys/password
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [API Reference](docs/api-reference.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Deployment](docs/deployment.md)

## Testing

```bash
go test ./...                    # All tests (requires age)
go test ./e2e/ -v -count=1      # E2E tests only
```
