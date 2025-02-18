package set1

import (
	"encoding/hex"
)

// RepeatingKeyXOR encrypts plaintext using a repeating-key XOR method.
func RepeatingKeyXOR(plaintext, key string) string {
	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)
	encrypted := make([]byte, len(plaintextBytes))

	for i := range plaintextBytes {
		encrypted[i] = plaintextBytes[i] ^ keyBytes[i%len(keyBytes)] // XOR with repeating key
	}

	return hex.EncodeToString(encrypted) // Convert encrypted bytes to hex string
}
