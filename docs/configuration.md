# SopsGate — Configuration

SopsGate is configured via a YAML file, passed with `-config` flag (default: `config.yaml`).

## Full Configuration

```yaml
server:
  address: ":8080"              # Listen address (default: ":8080")

storage:
  repo_path: "/data/secrets"    # Path to git repo for encrypted secrets (required)
  remote_url: ""                # Git remote URL (future: auto-push)
  auto_push: false              # Push to remote after each commit (future)

auth:
  tokens:                       # Static API tokens
    - name: "admin"             # Human-readable name (used in commit messages)
      token: "sk-..."           # Bearer token value

sops:
  age_key_file: "/path/to/key"  # Path to age private key file (required)
```

## Required Fields

| Field | Description |
|-------|-------------|
| `storage.repo_path` | Directory for the git-backed secrets repo. Created automatically if it doesn't exist. |
| `sops.age_key_file` | Path to an age key file generated with `age-keygen`. Contains both private key and public key (as comment). |

## Environment

SopsGate sets `SOPS_AGE_KEY_FILE` internally to the configured `age_key_file` path. This is required for the SOPS keyservice to decrypt data keys.

## Auth Tokens

Each token has a `name` and `token` value. The name appears in git commit messages for audit trails:

```
[sopsgate] PUT myapp/db_password by admin
```

Multiple tokens can be configured for different services/users.
