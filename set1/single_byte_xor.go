package set1

import (
	"unicode"
	"strings"
)

// SingleByteXOR decrypts a byte slice XOR'd against a single-byte key.
func SingleByteXOR(ciphertext []byte) (byte, string, error) {
	var bestKey byte
	var bestScore float64
	var bestPlaintext string

	// Try every possible single-byte key (0-255)
	for k := byte(0); k < 255; k++ {
		decrypted := make([]byte, len(ciphertext))

		// XOR every byte with the candidate key
		for i := range ciphertext {
			decrypted[i] = ciphertext[i] ^ k
		}

		// Score the decrypted text
		score := ScoreText(string(decrypted))

		// Keep the best result
		if score > bestScore {
			bestScore = score
			bestKey = k
			bestPlaintext = string(decrypted)
		}
	}

	return bestKey, bestPlaintext, nil
}

// ScoreText evaluates how "English-like" a given text is.
func ScoreText(text string) float64 {
	score := 0.0
	englishFreq := "etaoin shrdlu" // Common English letters

	for _, char := range text {
		if unicode.IsLetter(char) || char == ' ' {
			score++
		}
		if strings.ContainsRune(englishFreq, char) {
			score += 1.5
		}
		if char < 32 || char > 126 { // Penalize non-printable ASCII
			score -= 2
		}
	}

	return score / float64(len(text)) // Normalize score
}
