package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetAlphabetic   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetNumeric      = "0123456789"
	charsetFull         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

	MaxGenerateLength     = 1024
	DefaultPasswordLength = 32
	DefaultHexLength      = 64
	DefaultBase64Bytes    = 32
)

// GenerateRequest describes what kind of secret to generate.
type GenerateRequest struct {
	Type    string `json:"type"`              // "password", "hex", "base64"
	Length  int    `json:"length,omitempty"`   // output length (chars for password/hex, bytes for base64)
	Charset string `json:"charset,omitempty"` // for password: "alphanumeric", "alphabetic", "numeric", "full"
}

// Validate checks that the request is well-formed and fills in defaults.
func (r *GenerateRequest) Validate() error {
	switch r.Type {
	case "password":
		if r.Length == 0 {
			r.Length = DefaultPasswordLength
		}
		if r.Charset == "" {
			r.Charset = "full"
		}
		switch r.Charset {
		case "alphanumeric", "alphabetic", "numeric", "full":
		default:
			return fmt.Errorf("invalid charset %q: must be alphanumeric, alphabetic, numeric, or full", r.Charset)
		}
	case "hex":
		if r.Length == 0 {
			r.Length = DefaultHexLength
		}
		if r.Length%2 != 0 {
			return fmt.Errorf("hex length must be even, got %d", r.Length)
		}
	case "base64":
		if r.Length == 0 {
			r.Length = DefaultBase64Bytes
		}
	case "":
		return fmt.Errorf("type is required")
	default:
		return fmt.Errorf("invalid type %q: must be password, hex, or base64", r.Type)
	}

	if r.Length < 1 || r.Length > MaxGenerateLength {
		return fmt.Errorf("length must be between 1 and %d, got %d", MaxGenerateLength, r.Length)
	}

	return nil
}

// GenerateSecret produces a cryptographically random secret.
// The caller should defer ZeroBytes on the returned slice.
func GenerateSecret(req GenerateRequest) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch req.Type {
	case "password":
		return generatePassword(req.Length, req.Charset)
	case "hex":
		return generateHex(req.Length)
	case "base64":
		return generateBase64(req.Length)
	default:
		return nil, fmt.Errorf("unknown type: %s", req.Type)
	}
}

func generatePassword(length int, charset string) ([]byte, error) {
	var chars string
	switch charset {
	case "alphanumeric":
		chars = charsetAlphanumeric
	case "alphabetic":
		chars = charsetAlphabetic
	case "numeric":
		chars = charsetNumeric
	default:
		chars = charsetFull
	}

	result := make([]byte, length)
	max := big.NewInt(int64(len(chars)))
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("crypto/rand: %w", err)
		}
		result[i] = chars[n.Int64()]
	}
	return result, nil
}

func generateHex(length int) ([]byte, error) {
	raw := make([]byte, length/2)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	result := []byte(hex.EncodeToString(raw))
	ZeroBytes(raw)
	return result, nil
}

func generateBase64(numBytes int) ([]byte, error) {
	raw := make([]byte, numBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	result := []byte(base64.StdEncoding.EncodeToString(raw))
	ZeroBytes(raw)
	return result, nil
}
