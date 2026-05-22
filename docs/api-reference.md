# SopsGate — API Reference

Base URL: `/api/v1`

All endpoints (except `/healthz`) require authentication via `Authorization: Bearer <token>` header.

---

## Health

### `GET /healthz`

Returns server health status. No authentication required.

**Response:** `200 OK`
```json
{"status": "ok"}
```

---

## Namespaces

### `GET /api/v1/namespaces`

List all namespaces.

**Response:** `200 OK`
```json
{
  "namespaces": ["infra/postgres", "apps/myapp"]
}
```

### `POST /api/v1/namespaces/{namespace}`

Create a new namespace. The namespace can contain slashes for hierarchical organization (e.g., `infra/postgres`).

**Response:** `201 Created` | `409 Conflict` (already exists)

### `DELETE /api/v1/namespaces/{namespace}`

Delete a namespace and all its secrets.

**Response:** `200 OK` | `404 Not Found`

---

## Secrets

### `GET /api/v1/secrets/{namespace}`

List all secret key names in a namespace (values not included).

**Response:** `200 OK`
```json
{
  "namespace": "myapp",
  "keys": ["db_password", "api_key"]
}
```

### `GET /api/v1/secrets/{namespace}?reveal=true`

Get all secrets in a namespace with their values.

**Response:** `200 OK`
```json
{
  "namespace": "myapp",
  "secrets": {
    "db_password": "super-secret",
    "api_key": "key-123"
  }
}
```

### `GET /api/v1/secrets/{namespace}/keys/{key}`

Get a single secret value.

**Response:** `200 OK`
```json
{
  "namespace": "myapp",
  "key": "db_password",
  "value": "super-secret",
  "version": "a3f8c2d",
  "updated_at": "2026-05-22T10:30:00Z"
}
```

### `PUT /api/v1/secrets/{namespace}/keys/{key}`

Create or update a secret.

**Request body:**
```json
{"value": "super-secret-123"}
```

**Response:** `200 OK` | `400 Bad Request` | `404 Not Found` (namespace doesn't exist)

### `DELETE /api/v1/secrets/{namespace}/keys/{key}`

Delete a secret.

**Response:** `200 OK` | `404 Not Found`

### `PUT /api/v1/secrets/{namespace}`

Bulk upsert multiple secrets in a namespace.

**Request body:**
```json
{
  "secrets": {
    "db_password": "secret1",
    "api_key": "secret2"
  }
}
```

**Response:** `200 OK` | `400 Bad Request`

---

## Versioning

### `GET /api/v1/secrets/{namespace}/keys/{key}/versions`

List version history for a secret (derived from git commit history).

**Response:** `200 OK`
```json
{
  "namespace": "myapp",
  "key": "db_password",
  "versions": [
    {"version": "a3f8c2d", "committed_at": "2026-05-22T10:30:00Z", "message": "[sopsgate] PUT myapp/db_password by admin"},
    {"version": "b1e4f7a", "committed_at": "2026-05-20T08:00:00Z", "message": "[sopsgate] PUT myapp/db_password by admin"}
  ]
}
```

### `GET /api/v1/secrets/{namespace}/keys/{key}/versions/{version}`

Get a secret's value at a specific version (commit hash).

**Response:** `200 OK`
```json
{
  "namespace": "myapp",
  "key": "db_password",
  "value": "old-secret",
  "version": "b1e4f7a"
}
```

---

## Secret Generation

### `POST /api/v1/secrets/{namespace}/keys/{key}/generate`

Generate a cryptographically random secret and store it.

**Request body:**
```json
{
  "type": "password",
  "length": 32,
  "charset": "alphanumeric"
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `type` | yes | — | `password`, `hex`, or `base64` |
| `length` | no | type-dependent | Output length (chars for password/hex, bytes for base64) |
| `charset` | no | `full` | For `password` only: `alphanumeric`, `alphabetic`, `numeric`, `full` |

**Defaults:** password=32 chars, hex=64 chars, base64=32 bytes.

**Response:** `201 Created`
```json
{
  "namespace": "myapp",
  "key": "db_password",
  "value": "x7!kQ9m2Lp...",
  "version": "a3f8c2d"
}
```

---

## Error Responses

All errors return:
```json
{
  "error": "Not Found",
  "message": "key \"missing_key\" not found"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request (missing value, empty body) |
| `401` | Unauthorized (missing/invalid token) |
| `404` | Namespace or key not found |
| `409` | Conflict (namespace already exists) |
| `500` | Internal server error |
