package recon

import (
	"fmt"
	"os"
)

const filename string = "useful-clientids.txt"

func ForbiddenSuggestion() {
	body, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println("!!!!!!!!!!!!")
	fmt.Println("You are not allowed to view this resource, please check your access token or use one of these client IDs")
	fmt.Println("!!!!!!!!!!!!")
	fmt.Println(string(body))
}
