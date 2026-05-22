package store

// ZeroBytes overwrites every byte in b with zero.
// Use to scrub plaintext secrets from memory after use.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroSecretMap zeros every value slice in the map and deletes all entries.
// Use with defer to ensure decrypted secret values don't linger in memory.
func ZeroSecretMap(m map[string][]byte) {
	for k, v := range m {
		ZeroBytes(v)
		delete(m, k)
	}
}
