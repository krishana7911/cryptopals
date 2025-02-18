package set2

import (
	"errors"
	"fmt"
)

// PKCS7Pad applies PKCS#7 padding to a plaintext.
func PKCS7Pad(plaintext []byte, blockSize int) []byte {
	paddingNeeded := blockSize - (len(plaintext) % blockSize)
	padding := make([]byte, paddingNeeded)
	for i := range padding {
		padding[i] = byte(paddingNeeded)
	}
	return append(plaintext, padding...)
}

// PKCS7Unpad removes PKCS#7 padding after decryption.
func PKCS7Unpad(padded []byte) ([]byte, error) {
	if len(padded) == 0 {
		return nil, errors.New("padding error: input is empty")
	}

	// Get the last byte to determine the padding length
	paddingLen := int(padded[len(padded)-1])

	// Check for invalid padding length
	if paddingLen == 0 || paddingLen > len(padded) {
		return nil, errors.New("padding error: invalid padding length")
	}

	// Verify that all padding bytes are the same
	for _, p := range padded[len(padded)-paddingLen:] {
		if int(p) != paddingLen {
			return nil, errors.New("padding error: inconsistent padding")
		}
	}

	return padded[:len(padded)-paddingLen], nil
}


// Test the function
func TestPKCS7() {
	example := "YELLOW SUBMARINE"
	blockSize := 20

	padded := PKCS7Pad([]byte(example), blockSize)
	fmt.Printf("Original: %q\nPadded: %q\n", example, padded)
}
