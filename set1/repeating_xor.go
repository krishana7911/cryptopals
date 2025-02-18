package set1

import (
	"sort"
)

// HammingDistance computes the number of differing bits between two byte slices.
func HammingDistance(b1, b2 []byte) int {
	if len(b1) != len(b2) {
		panic("Inputs must have the same length")
	}

	distance := 0
	for i := range b1 {
		diff := b1[i] ^ b2[i] // XOR to find different bits
		for diff > 0 {
			distance += int(diff & 1) // Count 1s
			diff >>= 1
		}
	}
	return distance
}

// GuessKeySize finds the most likely KEYSIZE for a repeating-key XOR cipher.
func GuessKeySize(ciphertext []byte) int {
	type KeySizeScore struct {
		KeySize int
		Score   float64
	}

	var keysizeScores []KeySizeScore

	for keysize := 4; keysize <= 40; keysize++ { // ✅ Ignore KEYSIZE < 4
		if len(ciphertext) < keysize*4 {
			continue // Ensure enough data
		}

		// Extract 4 KEYSIZE-length blocks
		block1 := ciphertext[:keysize]
		block2 := ciphertext[keysize : 2*keysize]
		block3 := ciphertext[2*keysize : 3*keysize]
		block4 := ciphertext[3*keysize : 4*keysize]

		// Compute Hamming distances
		D1 := float64(HammingDistance(block1, block2))
		D2 := float64(HammingDistance(block2, block3))
		D3 := float64(HammingDistance(block3, block4))

		// Average the distances and normalize
		normalizedDistance := (D1 + D2 + D3) / (3 * float64(keysize))

		// Store KEYSIZE and its normalized distance
		keysizeScores = append(keysizeScores, KeySizeScore{KeySize: keysize, Score: normalizedDistance})
	}

	// Sort KEYSIZEs based on lowest normalized distance
	sort.Slice(keysizeScores, func(i, j int) bool {
		return keysizeScores[i].Score < keysizeScores[j].Score
	})

	// Return the best KEYSIZE
	return keysizeScores[0].KeySize
}

// BreakIntoBlocks groups ciphertext bytes by KEYSIZE.
func BreakIntoBlocks(ciphertext []byte, keysize int) [][]byte {
	blocks := make([][]byte, keysize)

	for i := range blocks {
		blocks[i] = make([]byte, 0)
	}

	for i, b := range ciphertext {
		blocks[i%keysize] = append(blocks[i%keysize], b)
	}

	return blocks
}

// BreakRepeatingKeyXOR cracks repeating-key XOR using single-byte XOR analysis.
func BreakRepeatingKeyXOR(ciphertext []byte, keysize int) []byte {
	blocks := BreakIntoBlocks(ciphertext, keysize)
	key := make([]byte, keysize)

	for i, block := range blocks {
		bestKey, _, _ := SingleByteXOR(block) // ✅ Pass `[]byte` directly
		key[i] = bestKey
	}

	return key
}

// RepeatingKeyXORDecrypt decrypts ciphertext using a found key.
func RepeatingKeyXORDecrypt(ciphertext, key []byte) []byte {
	plaintext := make([]byte, len(ciphertext))

	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ key[i%len(key)]
	}

	return plaintext
}
