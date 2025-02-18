package challenges

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cryptopals/set1"
)

// RunSet1 handles all Set 1 challenges
func RunSet1() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nSet 1 Challenges:")
	fmt.Println("1: Convert Hex to Base64")
	fmt.Println("2: XOR Two Hex Strings")
	fmt.Println("3: Single-Byte XOR Cipher")
	fmt.Println("4: Repeating-Key XOR Encryption")
	fmt.Println("5: Break Repeating-Key XOR (Challenge 6)")
	fmt.Println("6: Encrypt a Message Using Repeating-Key XOR")
	fmt.Println("7: Decrypt AES-128-ECB")
	fmt.Println("8: Detect AES-ECB in Ciphertexts")
	fmt.Print("Enter choice (1-8): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		fmt.Print("Enter hex string: ")
		hexString, _ := reader.ReadString('\n')
		hexString = strings.TrimSpace(hexString)

		base64String, err := set1.HexToBase64(hexString)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("Base64:", base64String)

	case "2":
		fmt.Print("Enter first hex string: ")
		hex1, _ := reader.ReadString('\n')
		hex1 = strings.TrimSpace(hex1)

		fmt.Print("Enter second hex string: ")
		hex2, _ := reader.ReadString('\n')
		hex2 = strings.TrimSpace(hex2)

		xorResult, err := set1.XorHexStrings(hex1, hex2)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("XOR Result:", xorResult)

	case "3":
		fmt.Print("Enter hex-encoded XOR'd string: ")
		hexString, _ := reader.ReadString('\n')
		hexString = strings.TrimSpace(hexString)

		_, plaintext, err := set1.SingleByteXOR([]byte(hexString))
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("Decrypted Message:", plaintext)

	case "4":
		fmt.Print("Enter plaintext: ")
		plaintext, _ := reader.ReadString('\n')

		fmt.Print("Enter key: ")
		key, _ := reader.ReadString('\n')

		encrypted := set1.RepeatingKeyXOREncrypt(strings.TrimSpace(plaintext), strings.TrimSpace(key))
		fmt.Println("Encrypted (Hex):", encrypted)

	case "5":
		ciphertext, err := set1.ReadBase64File("data/challenge6.txt")
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		keysize := set1.GuessKeySize(ciphertext)
		key := set1.BreakRepeatingKeyXOR(ciphertext, keysize)
		plaintext := set1.RepeatingKeyXORDecrypt(ciphertext, key)

		fmt.Println("Recovered Key:", string(key))
		fmt.Println("\nDecrypted Message:\n", string(plaintext))

	case "6":
		fmt.Print("Enter plaintext: ")
		plaintext, _ := reader.ReadString('\n')

		fmt.Print("Enter key: ")
		key, _ := reader.ReadString('\n')

		encrypted := set1.RepeatingKeyXOREncrypt(strings.TrimSpace(plaintext), strings.TrimSpace(key))
		fmt.Println("Encrypted (Hex):", encrypted)

	case "7":
		fmt.Print("Enter the path to the Base64-encoded AES-ECB file: ")
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)

		key := []byte("YELLOW SUBMARINE")
		ciphertext, err := set1.ReadBase64File(filePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		plaintext, err := set1.DecryptAES128ECB(ciphertext, key)
		if err != nil {
			fmt.Println("Decryption failed:", err)
			return
		}

		fmt.Println("\nDecrypted Message:\n", string(plaintext))

	case "8":
		fmt.Print("Enter the path to the hex-encoded ciphertext file: ")
		filePath, _ := reader.ReadString('\n')
		filePath = strings.TrimSpace(filePath)

		lineNumber, ecbCiphertext, err := set1.DetectECBFromFile(filePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		if lineNumber != -1 {
			fmt.Printf("ECB-encrypted ciphertext found on line %d:\n%s\n", lineNumber, ecbCiphertext)
		} else {
			fmt.Println("No ECB-encrypted ciphertext found.")
		}

	default:
		fmt.Println("Invalid choice! Please enter 1-8.")
	}
}
