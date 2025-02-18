package set1

import (
	"encoding/hex"
	"os"
	"strings"
)

// DetectECB checks if a ciphertext is likely encrypted using AES-128 in ECB mode.
func DetectECB(ciphertext []byte, blockSize int) bool {
	blockCount := len(ciphertext) / blockSize
	seenBlocks := make(map[string]bool)

	for i := 0; i < blockCount; i++ {
		block := string(ciphertext[i*blockSize : (i+1)*blockSize])

		// If we've seen this block before, ECB mode is likely
		if seenBlocks[block] {
			return true
		}
		seenBlocks[block] = true
	}

	return false
}

// DetectECBFromFile scans a file for ECB-encrypted ciphertexts.
func DetectECBFromFile(filename string) (int, string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 0, "", err
	}

	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		ciphertext, err := hex.DecodeString(strings.TrimSpace(line))
		if err != nil {
			continue
		}

		if DetectECB(ciphertext, 16) {
			return i + 1, line, nil // Return line number (1-based) and the ECB-encrypted ciphertext
		}
	}

	return -1, "", nil // No ECB-encrypted ciphertext found
}
