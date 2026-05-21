# SopsGate

Self-hosted HTTP secrets management service backed by SOPS encryption and Git versioning.

## Project Structure

```
cmd/server/main.go          # Entry point — config, DI wiring, HTTP server
internal/
  api/                      # HTTP handlers, router (net/http ServeMux), auth middleware
  config/                   # YAML config loading and validation
  model/                    # Domain types (Secret, PutSecretRequest, etc.)
  service/                  # Business logic — coordinates SOPS + Git, per-namespace locking
  store/
    sops.go                 # SOPS encrypt/decrypt via Go library (age keys)
    git.go                  # Git-backed storage via go-git (commit, history, file-at-commit)
e2e/                        # End-to-end tests (real SOPS + real git in temp dirs)
third_party/sops/           # SOPS source as git submodule (--depth 1)
docs/                       # Documentation (architecture, API reference, config, deployment, getting started)
```

## Key Architecture Decisions

- **SOPS as git submodule**, NOT a remote go.mod dependency. `go.mod` uses `replace github.com/getsops/sops/v3 => ./third_party/sops`
- **net/http standard library** — no chi or third-party routers. Uses `{rest...}` catch-all wildcard with manual `parseSecretsPath()` splitting on `/keys/` delimiter for nested namespace support
- **age encryption** — SOPS age key file path set via `os.Setenv("SOPS_AGE_KEY_FILE", ...)` because SOPS keyservice internally calls `MasterKey.Decrypt()` which reads from env
- **go-git** for all git operations — no shelling out to git CLI
- **Two-level locking**: per-namespace mutex in service layer + global mutex in GitStore for commit serialization

## Building and Running

```bash
go build -o sopsgate ./cmd/server
./sopsgate -config config.yaml
```

Config requires `storage.repo_path` and `sops.age_key_file`.

## Testing

```bash
# All tests (requires `age-keygen` installed: brew install age)
go test ./... -count=1

# E2E only
go test ./e2e/ -v -count=1
```

Tests create temp dirs with real age keys, real SOPS encryption, and real git repos. No mocks.

## Common Pitfalls

- **SOPS `yaml.NewStore`** requires a non-nil config: `yamlstore.NewStore(&sopsconfig.YAMLStoreConfig{Indent: 4})` — passing `nil` causes a nil pointer panic
- **Concurrent writes with identical values** can produce identical SOPS ciphertext, causing "clean working tree" git commit errors. Always use unique values in concurrent write tests
- **`parseAgeRecipients`** parses `# public key: <recipient>` lines from age key files — the prefix is 14 chars, not 15

## API

Base path: `/api/v1`. Bearer token auth on all routes except `/healthz`.

- `GET/POST/DELETE /namespaces/{ns}` — namespace CRUD
- `GET/PUT/DELETE /secrets/{ns}/keys/{key}` — secret CRUD
- `GET /secrets/{ns}/keys/{key}/versions` — version history
- `GET /secrets/{ns}/keys/{key}/versions/{hash}` — secret at version
- `GET /secrets/{ns}?reveal=true` — bulk get all secrets
- `PUT /secrets/{ns}` — bulk put secrets
