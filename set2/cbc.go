package set2

import (
	"crypto/aes"
	"errors"
)

// XORBytes performs XOR operation between two byte slices.
func XORBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// EncryptAES128CBC encrypts plaintext using AES-128-CBC mode.
func EncryptAES128CBC(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != 16 || len(iv) != 16 {
		return nil, errors.New("key and IV must be 16 bytes long")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Ensure plaintext is padded to 16-byte blocks
	plaintext = PKCS7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	prevBlock := iv

	for i := 0; i < len(plaintext); i += aes.BlockSize {
		// XOR the plaintext block with the previous ciphertext (or IV for the first block)
		xored := XORBytes(plaintext[i:i+aes.BlockSize], prevBlock)

		// Encrypt the XORed block using AES-ECB
		block.Encrypt(ciphertext[i:i+aes.BlockSize], xored)

		// Update the previous block for the next round
		prevBlock = ciphertext[i : i+aes.BlockSize]
	}

	return ciphertext, nil
}

// DecryptAES128CBC decrypts ciphertext using AES-128-CBC mode.
func DecryptAES128CBC(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 16 || len(iv) != 16 {
		return nil, errors.New("key and IV must be 16 bytes long")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	prevBlock := iv

	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		// Decrypt the current ciphertext block using AES-ECB
		decrypted := make([]byte, aes.BlockSize)
		block.Decrypt(decrypted, ciphertext[i:i+aes.BlockSize])

		// XOR with the previous ciphertext block (or IV for the first block)
		copy(plaintext[i:i+aes.BlockSize], XORBytes(decrypted, prevBlock))

		// Update the previous block for the next round
		prevBlock = ciphertext[i : i+aes.BlockSize]
	}

	// Remove padding
	return PKCS7Unpad(plaintext)
}
