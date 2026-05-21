# SopsGate — Getting Started

## Prerequisites

- **Go 1.25+**
- **age** — for key generation (`brew install age` or [age releases](https://github.com/FiloSottile/age/releases))
- **git** — for the backing secret store

## 1. Generate an age key

```bash
age-keygen -o sopsgate.key
```

This creates a file with your private key and a comment containing the public key.

## 2. Create a config file

```yaml
# config.yaml
server:
  address: ":8080"

storage:
  repo_path: "./secrets-repo"

auth:
  tokens:
    - name: admin
      token: "sk-my-secret-token"

sops:
  age_key_file: "./sopsgate.key"
```

## 3. Build and run

```bash
# Clone with submodules
git clone --recurse-submodules <repo-url>
cd sopsgate

# Build
go build -o sopsgate ./cmd/server

# Run
./sopsgate -config config.yaml
```

The server starts on `:8080`. A git repo is automatically initialized at `./secrets-repo`.

## 4. Use the API

```bash
TOKEN="sk-my-secret-token"
BASE="http://localhost:8080/api/v1"

# Create a namespace
curl -X POST -H "Authorization: Bearer $TOKEN" $BASE/namespaces/myapp

# Store a secret
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"super-secret-123"}' \
  $BASE/secrets/myapp/keys/db_password

# Read it back
curl -H "Authorization: Bearer $TOKEN" $BASE/secrets/myapp/keys/db_password

# List keys in namespace
curl -H "Authorization: Bearer $TOKEN" $BASE/secrets/myapp

# Get all secrets (values revealed)
curl -H "Authorization: Bearer $TOKEN" "$BASE/secrets/myapp?reveal=true"

# View version history
curl -H "Authorization: Bearer $TOKEN" $BASE/secrets/myapp/keys/db_password/versions

# Health check (no auth required)
curl http://localhost:8080/healthz
```

## 5. Docker

```bash
docker build -t sopsgate .
docker run -p 8080:8080 \
  -v ./config.yaml:/app/config.yaml \
  -v ./sopsgate.key:/app/sopsgate.key \
  -v ./secrets-repo:/data/secrets-repo \
  sopsgate
```
