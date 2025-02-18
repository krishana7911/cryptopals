package set1

import (
	"crypto/aes"
)

// DecryptAES128ECB decrypts AES-128-ECB encrypted data using a given key.
func DecryptAES128ECB(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	// Decrypt each 16-byte block independently (ECB mode)
	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}
