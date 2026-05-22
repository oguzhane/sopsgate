package store

import (
	"testing"
)

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-secret-data")
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	// Should not panic.
	ZeroBytes(nil)
	ZeroBytes([]byte{})
}

func TestZeroSecretMap(t *testing.T) {
	m := map[string][]byte{
		"key1": []byte("secret-value-1"),
		"key2": []byte("secret-value-2"),
	}
	// Keep references to the backing slices.
	ref1 := m["key1"]
	ref2 := m["key2"]

	ZeroSecretMap(m)

	if len(m) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(m))
	}
	// Verify the original backing arrays are zeroed.
	for i, b := range ref1 {
		if b != 0 {
			t.Fatalf("ref1[%d] not zeroed: got %d", i, b)
		}
	}
	for i, b := range ref2 {
		if b != 0 {
			t.Fatalf("ref2[%d] not zeroed: got %d", i, b)
		}
	}
}

func TestZeroSecretMap_Nil(t *testing.T) {
	// Should not panic.
	ZeroSecretMap(nil)
}

func TestSOPSEngine_DecryptZerosDataKey(t *testing.T) {
	keyFile := generateAgeKey(t)
	engine, err := NewSOPSEngine([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := engine.EncryptMap(map[string][]byte{"k": []byte("v")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt returns map[string][]byte — verify we can zero the values.
	secrets, err := engine.DecryptFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	val := secrets["k"]
	if string(val) != "v" {
		t.Fatalf("expected 'v', got %q", val)
	}

	// Zero and verify.
	ZeroSecretMap(secrets)
	for i, b := range val {
		if b != 0 {
			t.Fatalf("val[%d] not zeroed: got %d", i, b)
		}
	}
}
