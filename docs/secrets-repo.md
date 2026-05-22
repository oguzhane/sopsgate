# SopsGate — Secrets Repo Structure

The secrets repo is the git-backed directory at `storage.repo_path` where SopsGate stores all encrypted secrets.

## Basic Setup (single key)

With one age key and no `.sops.yaml`, SopsGate creates this structure automatically:

```
secrets-repo/
├── secrets/
│   ├── myapp.sops.yaml              # namespace: myapp
│   ├── postgres.sops.yaml           # namespace: postgres
│   └── infra/
│       └── redis.sops.yaml          # namespace: infra/redis
```

Each namespace maps to one SOPS-encrypted YAML file containing all key-value pairs for that namespace.

## Multi-tenant Setup (multiple keys, `.sops.yaml`)

For separate encryption keys per environment:

```
secrets-repo/
├── .sops.yaml                        # creation rules (which key encrypts what)
├── secrets/
│   ├── dev/
│   │   ├── api.sops.yaml            # namespace: dev/api     → encrypted with dev key
│   │   └── db.sops.yaml             # namespace: dev/db      → encrypted with dev key
│   ├── staging/
│   │   └── api.sops.yaml            # namespace: staging/api → encrypted with staging key
│   └── prod/
│       ├── api.sops.yaml            # namespace: prod/api    → encrypted with prod key
│       └── payments.sops.yaml       # namespace: prod/payments → encrypted with prod key
```

### `.sops.yaml` (in the repo root)

```yaml
creation_rules:
  # Dev secrets — encrypted with dev team's age key
  - path_regex: secrets/dev/.*
    age: 'age1dev...(public key)'

  # Staging — encrypted with staging key
  - path_regex: secrets/staging/.*
    age: 'age1staging...(public key)'

  # Prod — encrypted with prod key + ops backup key (both can decrypt)
  - path_regex: secrets/prod/.*
    age: >-
      age1prod...(public key),
      age1opsbackup...(public key)

  # Catch-all for anything else
  - age: 'age1default...(public key)'
```

Rules are evaluated top-down; the first `path_regex` match wins.

### SopsGate config for this setup

```yaml
storage:
  repo_path: "/data/secrets-repo"

sops:
  age_key_files:
    - "/etc/sopsgate/dev.key"       # dev private key
    - "/etc/sopsgate/staging.key"   # staging private key
    - "/etc/sopsgate/prod.key"      # prod private key
```

## Request Flow Example

### Creating a namespace

```
POST /api/v1/namespaces/prod/payments
  → resolves path: secrets/prod/payments.sops.yaml
  → reads .sops.yaml → matches "secrets/prod/.*" → selects age1prod + age1opsbackup
  → creates empty encrypted file with prod recipients
```

### Writing a secret

```
PUT /api/v1/secrets/prod/payments/keys/stripe_key
  → reads secrets/prod/payments.sops.yaml (ciphertext from disk)
  → decrypts in memory (tries all loaded identities → prod.key matches)
  → sets stripe_key in memory map
  → re-encrypts with same embedded recipients (prod + ops backup)
  → writes ciphertext to disk, git commits
```

### Reading a secret

```
GET /api/v1/secrets/prod/payments/keys/stripe_key
  → reads ciphertext from disk
  → decrypts in memory using matching identity
  → returns value in HTTP response (never touches disk as plaintext)
```

## Importing Existing SOPS Files

Files encrypted outside SopsGate can be served directly — just drop them into the repo:

```bash
# User's existing workflow
sops --encrypt --age age1prod... myfile.yaml > secrets/prod/legacy.sops.yaml
```

SopsGate will decrypt and serve `legacy.sops.yaml` as long as the matching private key is in `age_key_files`. No re-encryption needed.

## Inside a `.sops.yaml` File

Each namespace file is a standard SOPS-encrypted YAML:

```yaml
db_password: ENC[AES256_GCM,data:7mN2+Q==,iv:...,tag:...,type:str]
api_key: ENC[AES256_GCM,data:kP9x3A==,iv:...,tag:...,type:str]
sops:
    age:
        - recipient: age1prod...
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            ...
            -----END AGE ENCRYPTED FILE-----
        - recipient: age1opsbackup...
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            ...
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-05-22T13:00:00Z"
    mac: ENC[AES256_GCM,data:...,type:str]
    version: 3.9.0
```

Each value is individually encrypted. The `sops` metadata block records which recipients can decrypt — this is self-contained, so decryption only needs the matching private key, not the `.sops.yaml` rules.
