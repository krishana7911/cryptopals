package set2

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"math/big"
)

// GenerateRandomAESKey creates a random 16-byte AES key.
func GenerateRandomAESKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateRandomBytes creates a random byte slice of length n.
func GenerateRandomBytes(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// EncryptWithRandomMode chooses AES-ECB or AES-CBC randomly and encrypts data.
func EncryptWithRandomMode(input []byte) ([]byte, string, error) {
	key, err := GenerateRandomAESKey()
	if err != nil {
		return nil, "", err
	}

	// Generate random padding (5-10 bytes before & after the input)
	prependLen, _ := rand.Int(rand.Reader, big.NewInt(6))
	appendLen, _ := rand.Int(rand.Reader, big.NewInt(6))
	prependBytes, _ := GenerateRandomBytes(int(prependLen.Int64() + 5))
	appendBytes, _ := GenerateRandomBytes(int(appendLen.Int64() + 5))

	// Combine the padding with input
	modifiedInput := append(prependBytes, input...)
	modifiedInput = append(modifiedInput, appendBytes...)

	// PKCS#7 padding
	modifiedInput = PKCS7Pad(modifiedInput, aes.BlockSize)

	// Randomly select ECB (0) or CBC (1)
	mode, _ := rand.Int(rand.Reader, big.NewInt(2))

	if mode.Int64() == 0 {
		// Encrypt with AES-ECB
		ciphertext, err := EncryptAES128ECB(modifiedInput, key)
		if err != nil {
			return nil, "", err
		}
		return ciphertext, "ECB", nil
	} else {
		// Generate random IV
		iv, _ := GenerateRandomAESKey() // IV must also be 16 bytes
		ciphertext, err := EncryptAES128CBC(modifiedInput, key, iv)
		if err != nil {
			return nil, "", err
		}
		return ciphertext, "CBC", nil
	}
}

// DetectECBMode detects if a ciphertext was encrypted using AES-ECB.
func DetectECBMode(ciphertext []byte) bool {
	blockSize := aes.BlockSize
	blocks := make(map[string]bool)

	// Check for duplicate 16-byte blocks
	for i := 0; i < len(ciphertext)-blockSize; i += blockSize {
		block := string(ciphertext[i : i+blockSize])
		if blocks[block] {
			return true // Duplicate block found → likely ECB mode
		}
		blocks[block] = true
	}
	return false
}

// EncryptAES128ECB encrypts plaintext using AES-128-ECB mode.
func EncryptAES128ECB(plaintext, key []byte) ([]byte, error) {
	if len(key) != aes.BlockSize {
		return nil, errors.New("key must be 16 bytes long")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext must be a multiple of 16 bytes")
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	return ciphertext, nil
}

