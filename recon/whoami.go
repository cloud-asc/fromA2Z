package recon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func GetCurrentUser(access_token string, socks int) {
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
	var claims struct {
		DisplayName string `json:"name"`
		UPN         string `json:"upn"`
		OID         string `json:"oid"`
		TID         string `json:"tid"`
		AppID       string `json:"appid"`
		AppName     string `json:"app_displayname"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		fmt.Println("Error parsing token:", err)
		return
	}
	fmt.Println("\n--- Current User ---")
	fmt.Println("Display Name: ", claims.DisplayName)
	fmt.Println("UPN:          ", claims.UPN)
	fmt.Println("Object ID:    ", claims.OID)
	fmt.Println("Tenant ID:    ", claims.TID)
	fmt.Println("App ID:       ", claims.AppID)
	fmt.Println("App Name:     ", claims.AppName)
	fmt.Println("--------------------")
}
