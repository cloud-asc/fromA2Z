package recon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func GetCurrentUser(access_token string) {
	parts := strings.Split(access_token, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid token format")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		fmt.Println("Error parsing token:", err)
		return
	}

	// pretty print the JSON
	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		fmt.Println("Error formatting claims:", err)
		return
	}

	fmt.Println("\n--- Access Token ---")
	fmt.Println(string(pretty))
	fmt.Println("--------------------")
	fmt.Println("\nAccess Token:")
}
