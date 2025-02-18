package set1

import "testing"

func TestHexToBase64(t *testing.T) {
	tests := []struct {
		hexInput    string
		base64Output string
	}{
		{"48656c6c6f20576f726c64", "SGVsbG8gV29ybGQ="}, // "Hello World"
		{"4d616e", "TWFu"}, // "Man"
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
	}

	for _, tt := range tests {
		result, err := HexToBase64(tt.hexInput)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if result != tt.base64Output {
			t.Errorf("Expected %s, got %s", tt.base64Output, result)
		}
	}
}
