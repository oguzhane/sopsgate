// Package model defines the core domain types for sopsgate.
package model

import "time"

// Secret represents a single secret value within a namespace.
type Secret struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"`
	Version   string `json:"version,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// SecretVersion represents a historical version of a secret.
type SecretVersion struct {
	Version     string    `json:"version"`
	CommittedAt time.Time `json:"committed_at"`
	Message     string    `json:"message"`
}

// Namespace represents a logical grouping of secrets.
type Namespace struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Identity represents an authenticated caller.
type Identity struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"` // Future: path-based ACLs
}

// PutSecretRequest is the body for PUT /secrets/{ns}/{key}.
type PutSecretRequest struct {
	Value string `json:"value"`
}

// BulkPutRequest is the body for PUT /secrets/{ns}.
type BulkPutRequest struct {
	Secrets map[string]string `json:"secrets"`
}

// ListKeysResponse is the response for GET /secrets/{ns}.
type ListKeysResponse struct {
	Namespace string   `json:"namespace"`
	Keys      []string `json:"keys"`
}

// BulkGetResponse is the response for GET /secrets/{ns}?reveal=true.
type BulkGetResponse struct {
	Namespace string            `json:"namespace"`
	Secrets   map[string]string `json:"secrets"`
}

// VersionsResponse is the response for GET /secrets/{ns}/{key}/versions.
type VersionsResponse struct {
	Namespace string          `json:"namespace"`
	Key       string          `json:"key"`
	Versions  []SecretVersion `json:"versions"`
}

// NamespacesResponse is the response for GET /namespaces.
type NamespacesResponse struct {
	Namespaces []string `json:"namespaces"`
}

// GenerateSecretRequest is the body for POST /secrets/{ns}/keys/{key}/generate.
type GenerateSecretRequest struct {
	Type    string `json:"type"`              // "password", "hex", "base64"
	Length  int    `json:"length,omitempty"`   // output length
	Charset string `json:"charset,omitempty"` // for password: "alphanumeric", "alphabetic", "numeric", "full"
}

// GenerateSecretResponse is the response for POST /secrets/{ns}/keys/{key}/generate.
type GenerateSecretResponse struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Version   string `json:"version"`
}

// ErrorResponse is the standard error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
