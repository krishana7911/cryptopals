package challenges

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"cryptopals/set2"
)

// RunSet2 handles all Set 2 challenges
func RunSet2() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nSet 2 Challenges:")
	fmt.Println("1: Implement PKCS#7 Padding")
	fmt.Println("2: Implement AES-CBC Mode)")
	fmt.Println("3: Implement CBC Mode Padding Oracle")
	fmt.Print("Enter choice (1-3): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		fmt.Print("Enter plaintext: ")
		plaintext, _ := reader.ReadString('\n')
		plaintext = strings.TrimSpace(plaintext)

		fmt.Print("Enter block size: ")
		var blockSize int
		fmt.Scan(&blockSize)

		padded := set2.PKCS7Pad([]byte(plaintext), blockSize)
		fmt.Printf("Padded Output: %q\n", padded)

	case "2":
		fmt.Print("Enter the path to the Base64-encoded AES-CBC file: ")
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)

		// Read and decode the Base64 file
		ciphertext, err := set2.ReadBase64File(filePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		// Set the correct AES key and IV (all zeroes)
		key := []byte("YELLOW SUBMARINE") // ✅ 16-byte key
		iv := make([]byte, 16)             // ✅ IV of all zeroes

		// Decrypt using AES-128-CBC
		plaintext, err := set2.DecryptAES128CBC(ciphertext, key, iv)
		if err != nil {
			fmt.Println("Decryption error:", err)
			return
		}

		fmt.Println("\nDecrypted Message:\n", string(plaintext))

	case "3":
		fmt.Println("\nECB/CBC Detection Oracle")
		fmt.Println("1: Encrypt & Detect Mode")
		fmt.Println("2: Detect Mode from Given Ciphertext (Hex)")
		fmt.Print("Enter choice (1-2): ")

		modeChoice, _ := reader.ReadString('\n')
		modeChoice = strings.TrimSpace(modeChoice)

		if modeChoice == "1" {
			fmt.Println("Enter plaintext (Press ENTER twice to finish):")

			var lines []string
			for {
				line, _ := reader.ReadString('\n')
				line = strings.TrimRight(line, "\r\n")
				if line == "" { // Stop on empty line
					break
				}
				lines = append(lines, line)
			}

			// Combine all lines into a single message
			plaintext := strings.Join(lines, "\n")

			// Encrypt with a randomly chosen mode
			ciphertext, actualMode, err := set2.EncryptWithRandomMode([]byte(plaintext))
			if err != nil {
				fmt.Println("Encryption error:", err)
				return
			}

			// Detect the encryption mode
			detectedMode := "CBC"
			if set2.DetectECBMode(ciphertext) {
				detectedMode = "ECB"
			}

			// Print results
			fmt.Printf("Actual Mode: %s\n", actualMode)
			fmt.Printf("Detected Mode: %s\n", detectedMode)

			if detectedMode == actualMode {
				fmt.Println("✅ Correctly detected encryption mode!")
			} else {
				fmt.Println("❌ Incorrect detection! Something went wrong.")
			}

		} else if modeChoice == "2" {
			fmt.Println("Enter ciphertext (Hex format, multiple lines allowed). Press ENTER twice to finish:")

			var hexLines []string
			for {
				line, _ := reader.ReadString('\n')
				line = strings.TrimRight(line, "\r\n")
				if line == "" { // Stop when the user presses ENTER twice
					break
				}
				hexLines = append(hexLines, line)
			}

			// Combine all lines into a single hex string
			hexCiphertext := strings.Join(hexLines, "")

			// Convert hex string to byte slice
			ciphertext, err := hex.DecodeString(hexCiphertext)
			if err != nil {
				fmt.Println("Invalid hex input:", err)
				return
			}

			// Detect the encryption mode
			if set2.DetectECBMode(ciphertext) {
				fmt.Println("Detected Mode: ECB ✅")
			} else {
				fmt.Println("Detected Mode: CBC (or unknown) ✅")
			}

		} else {
			fmt.Println("Invalid choice! Please enter 1 or 2.")
		}


	default:
		fmt.Println("Invalid choice! Please enter 1-3.")
	}
}
