package set1

import (
	"encoding/base64"
	"os"
	"strings"
)

// ReadBase64File reads a Base64-encoded file and decodes it into raw bytes.
func ReadBase64File(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// ✅ Ensure newlines are removed before decoding
	cleanData := strings.ReplaceAll(string(data), "\n", "")

	ciphertext, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
