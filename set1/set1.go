package set1

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// HexToBase64 converts a hex string to a base64-encoded string.
func HexToBase64(hexString string) (string, error) {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", errors.New("invalid hex input")
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

// XorBuffers takes two equal-length byte slices and returns their XOR result.
func XorBuffers(buf1, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, errors.New("buffers must be of equal length")
	}

	result := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i++ {
		result[i] = buf1[i] ^ buf2[i] // XOR each byte
	}
	return result, nil
}

// XorHexStrings takes two equal-length hex-encoded strings and returns their XOR result as a hex string.
func XorHexStrings(hex1, hex2 string) (string, error) {
	buf1, err1 := hex.DecodeString(hex1)
	buf2, err2 := hex.DecodeString(hex2)

	if err1 != nil || err2 != nil {
		return "", errors.New("invalid hex input")
	}

	xorResult, err := XorBuffers(buf1, buf2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(xorResult), nil
}
