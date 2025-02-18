package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cryptopals/challenges" // ✅ Import the new package
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Cryptopals Challenge Solver")
	fmt.Println("1: Set 1 Challenges")
	fmt.Println("2: Set 2 Challenges")
	fmt.Print("Enter choice (1-2): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		challenges.RunSet1() // ✅ Calls `RunSet1()` from the `challenges` package
	case "2":
		challenges.RunSet2() // ✅ Calls `RunSet2()` from the `challenges` package
	default:
		fmt.Println("Invalid choice! Please enter 1 or 2.")
	}
}
