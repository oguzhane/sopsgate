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
  plugin:                       # Optional — age plugin support (e.g., age-plugin-yubikey)
    path_prepend:               # Directories to prepend to $PATH for plugin binary discovery
      - "/usr/local/bin"
    env:                        # Additional environment variables for plugins
      YKMAN_DEVICE: "12345678"
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

## Age Plugin Support

SopsGate supports age plugins (e.g., `age-plugin-yubikey`) for hardware-backed key decryption. Plugins follow the standard [age plugin protocol](https://github.com/C2SP/C2SP/blob/main/age.md) — the plugin binary is executed as a subprocess for each decrypt operation.

### Setup

1. **Add the plugin identity to a key file.** The identity line starts with `AGE-PLUGIN-` (e.g., `AGE-PLUGIN-YUBIKEY-1...`). It can be in the same file as X25519 keys or a separate file:

   ```
   # YubiKey identity
   AGE-PLUGIN-YUBIKEY-1QFGX3...
   ```

2. **Configure `path_prepend`** so SopsGate can find the plugin binary:

   ```yaml
   sops:
     age_key_files:
       - "./keys/yubikey-identity.txt"
     plugin:
       path_prepend:
         - "/usr/local/bin"       # Directory containing age-plugin-yubikey
   ```

3. **Optionally set plugin-specific env vars:**

   ```yaml
   sops:
     plugin:
       env:
         YKMAN_DEVICE: "12345678"   # For multi-YubiKey setups
   ```

### How It Works

- At startup, `path_prepend` directories are prepended to `$PATH` and `env` values are set
- When a secret is decrypted, SOPS loads identities from the configured key files
- For `AGE-PLUGIN-*` identities, SOPS executes the plugin binary (e.g., `age-plugin-yubikey`)
- The plugin handles the cryptographic operation (e.g., YubiKey touch for decryption)

### Limitations

| Limitation | Description |
|-----------|-------------|
| **Touch-only** | Only plugins that operate non-interactively (or with cached PINs) are supported. Interactive prompts (PIN entry) will fail on a headless server. |
| **Per-request** | Each decrypt triggers a plugin execution and (for YubiKey) requires a physical touch. There is no data key caching across requests. |
| **Timeout** | YubiKey has a ~15s hardware timeout. If touch doesn't happen, the request fails with a 500 error. |
| **Binary required** | The plugin binary (e.g., `age-plugin-yubikey`) must be available in `$PATH` or via `path_prepend`. |
