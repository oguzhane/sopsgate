package store

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestGenerateSecret_Password(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "password", Length: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	if len(result) != 32 {
		t.Fatalf("expected 32 chars, got %d", len(result))
	}
}

func TestGenerateSecret_PasswordAlphanumeric(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "password", Length: 100, Charset: "alphanumeric"})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	for _, c := range result {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Fatalf("unexpected char %q in alphanumeric password", string(c))
		}
	}
}

func TestGenerateSecret_PasswordAlphabetic(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "password", Length: 50, Charset: "alphabetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	for _, c := range result {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			t.Fatalf("unexpected char %q in alphabetic password", string(c))
		}
	}
}

func TestGenerateSecret_PasswordNumeric(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "password", Length: 20, Charset: "numeric"})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	for _, c := range result {
		if c < '0' || c > '9' {
			t.Fatalf("unexpected char %q in numeric password", string(c))
		}
	}
}

func TestGenerateSecret_Hex(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "hex", Length: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	if len(result) != 64 {
		t.Fatalf("expected 64 chars, got %d", len(result))
	}
	// Must be valid hex.
	if _, err := hex.DecodeString(string(result)); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
}

func TestGenerateSecret_Base64(t *testing.T) {
	result, err := GenerateSecret(GenerateRequest{Type: "base64", Length: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	decoded, err := base64.StdEncoding.DecodeString(string(result))
	if err != nil {
		t.Fatalf("not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 decoded bytes, got %d", len(decoded))
	}
}

func TestGenerateSecret_Defaults(t *testing.T) {
	// Password default length = 32.
	req := GenerateRequest{Type: "password"}
	result, err := GenerateSecret(req)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(result)
	if len(result) != DefaultPasswordLength {
		t.Fatalf("expected default length %d, got %d", DefaultPasswordLength, len(result))
	}
}

func TestGenerateSecret_InvalidType(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{Type: "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestGenerateSecret_EmptyType(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{})
	if err == nil {
		t.Fatal("expected error for empty type")
	}
}

func TestGenerateSecret_InvalidCharset(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{Type: "password", Charset: "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid charset")
	}
}

func TestGenerateSecret_OddHexLength(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{Type: "hex", Length: 33})
	if err == nil {
		t.Fatal("expected error for odd hex length")
	}
}

func TestGenerateSecret_TooLong(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{Type: "password", Length: MaxGenerateLength + 1})
	if err == nil {
		t.Fatal("expected error for length exceeding max")
	}
}

func TestGenerateSecret_ZeroLength(t *testing.T) {
	_, err := GenerateSecret(GenerateRequest{Type: "password", Length: -1})
	if err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestGenerateSecret_Uniqueness(t *testing.T) {
	// Generate two passwords — they should differ (probabilistically).
	a, _ := GenerateSecret(GenerateRequest{Type: "password", Length: 32})
	b, _ := GenerateSecret(GenerateRequest{Type: "password", Length: 32})
	if string(a) == string(b) {
		t.Fatal("two generated passwords should differ")
	}
	ZeroBytes(a)
	ZeroBytes(b)
}
