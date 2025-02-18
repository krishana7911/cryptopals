package set1

import (
	"encoding/hex"
)

// RepeatingKeyXOREncrypt encrypts a given plaintext using a repeating-key XOR cipher.
func RepeatingKeyXOREncrypt(plaintext, key string) string {
	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)
	encrypted := make([]byte, len(plaintextBytes))

	for i := range plaintextBytes {
		encrypted[i] = plaintextBytes[i] ^ keyBytes[i%len(keyBytes)]
	}

	return hex.EncodeToString(encrypted) // Convert to hex for readability
}
