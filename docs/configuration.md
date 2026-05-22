# SopsGate — Configuration

SopsGate is configured via a YAML file, passed with `-config` flag (default: `config.yaml`).

## Full Configuration

```yaml
server:
  address: ":8080"              # Listen address (default: ":8080")
  tls:                          # Optional — omit for plain HTTP
    cert_file: ""               # Server certificate (PEM)
    key_file: ""                # Server private key (PEM)
    client_ca_file: ""          # CA certificate for client verification (enables mTLS)

storage:
  repo_path: "/data/secrets"    # Path to git repo for encrypted secrets (required)
  remote_url: ""                # Git remote URL (future: auto-push)
  auto_push: false              # Push to remote after each commit (future)

auth:
  tokens:                       # Static API tokens
    - name: "admin"             # Human-readable name (used in commit messages)
      token: "sk-..."           # Bearer token value

sops:
  age_key_files:                # Paths to age private key files (optional if SOPS_AGE_KEY_FILE is set)
    - "/path/to/key1"
    - "/path/to/key2"           # Multiple keys for multi-tenant decryption
```

## Required Fields

| Field | Description |
|-------|-------------|
| `storage.repo_path` | Directory for the git-backed secrets repo. Created automatically if it doesn't exist. |

## SOPS Key Configuration

SopsGate needs age private keys for decryption. Keys can come from two sources (both are merged):

| Source | Description |
|--------|-------------|
| `sops.age_key_files` | List of age key file paths in the config file |
| `SOPS_AGE_KEY_FILE` env var | Standard SOPS env var pointing to an age key file |

At least one source must be provided. Multiple key files are supported — all identities are loaded and SOPS automatically uses the correct one for each encrypted file.

### `.sops.yaml` Creation Rules

When creating new namespaces, SopsGate reads `.sops.yaml` from the secrets repo root to determine which age recipients (public keys) to use for encryption. This follows the standard SOPS convention:

```yaml
# Place this in the secrets repo root (storage.repo_path)
creation_rules:
  - path_regex: secrets/prod\..*
    age: 'age1abc...'           # Production key
  - path_regex: secrets/dev\..*
    age: 'age1xyz...'           # Development key
  - age: 'age1default...'       # Catch-all
```

Rules are evaluated top-down; the first `path_regex` match wins. If no `.sops.yaml` exists, SopsGate uses the recipients from the configured age key files.

This means existing SOPS-encrypted files can be served by SopsGate without re-encryption — just provide the matching private keys.

## Auth Tokens

Each token has a `name` and `token` value. The name appears in git commit messages for audit trails:

```
[sopsgate] PUT myapp/db_password by admin
```

Multiple tokens can be configured for different services/users.

## TLS / Mutual TLS

SopsGate supports TLS and mutual TLS (mTLS). When mTLS is enabled, clients must present a certificate signed by the configured CA to connect. Bearer tokens are still required for identity — mTLS gates *who can connect*, tokens determine *which identity*.

### TLS only (server auth)

```yaml
server:
  address: ":8443"
  tls:
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
```

### Mutual TLS (client + server auth)

```yaml
server:
  address: ":8443"
  tls:
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    client_ca_file: "./certs/ca.crt"
```

| Field | Description |
|-------|-------------|
| `server.tls.cert_file` | Path to server certificate (PEM). Must be paired with `key_file`. |
| `server.tls.key_file` | Path to server private key (PEM). Must be paired with `cert_file`. |
| `server.tls.client_ca_file` | Path to CA certificate (PEM) for verifying client certificates. Requires `cert_file` and `key_file`. |

All fields are optional — if omitted, SopsGate runs plain HTTP. Certificates must be generated externally (e.g., with `openssl`, `step-ca`, or `mkcert`).
