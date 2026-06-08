package auth

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const authFile string = ".fromA2Z_auth"

type deviceCodeResponse struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type TokenResponse struct {
	Error        string `json:"error"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ErrorDesc    string `json:"error_description"`
	//ExpiresIn    int    `json:"expires_in"`
	ExpiresOn string `json:"expires_on,omitempty"`
}

type JWT struct {
	Aud          string   `json:"aud"`
	ClientId     string   `json:"appid"`
	ClientIdName string   `json:"app_displayname"`
	Scope        string   `json:"scp"`
	TID          string   `json:"tid"`
	UPN          string   `json:"upn"`
	Roles        []string `json:"roles"`
	Oid          string   `json:"oid"`
}

func CheckAuth() bool {
	if _, err := os.Stat(authFile); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("File '%s' does not exist.\n", authFile)
		return false
	}

	data, err := os.ReadFile(authFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return false
	}

	var authTokens TokenResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &authTokens); err != nil {
		fmt.Println(".fromA2Z_auth file corrupted")
		return false
	}

	if authTokens.AccessToken == "" {
		fmt.Println("No access token found in auth file")
		return false
	}

	// decode JWT payload
	parts := strings.Split(authTokens.AccessToken, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid token format")
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return false
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}

	if err := json.Unmarshal(decoded, &claims); err != nil {
		fmt.Println("Error parsing token claims:", err)
		return false
	}

	expTime := time.Unix(claims.Exp, 0).UTC()
	now := time.Now().UTC()

	if now.After(expTime) {
		fmt.Println("Access token expired on:", expTime.Format(time.RFC1123))
		return false
	}

	remaining := expTime.Sub(now)
	totalMinutes := int(remaining.Minutes())
	if totalMinutes == 60 {
		fmt.Println("Exactly 1 hour left!!")
	} else if totalMinutes > 60 {
		fmt.Printf("%d hours and %d minutes left!!\n\n", totalMinutes/60, totalMinutes%60)
	} else {
		fmt.Printf("%d minutes left!!\n\n", totalMinutes)
	}

	return true
}

func GetAccessToken() string {
	var authTokens TokenResponse
	data, err := os.ReadFile(authFile)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return ""
	}
	fileContents := string(data)
	cleanedJSON := strings.TrimSpace(fileContents)
	err = json.Unmarshal([]byte(cleanedJSON), &authTokens)
	return authTokens.AccessToken
}

func RequestDeviceCode(clientID string, tenantID string, scope string, socks int) (*deviceCodeResponse, error) {
	authority := "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/devicecode"

	client := newHttpClient(socks)

	resp, err := client.PostForm(authority, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":  {clientID},
		"scope":      {scope}})
	//"scope": {"openid"}})

	if err != nil {
		println("error")
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	//println(resp)
	body, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(body))
	var dcr deviceCodeResponse
	json.Unmarshal(body, &dcr)
	if dcr.DeviceCode == "" {
		fmt.Println("Invalid tenant entered")
		return nil, fmt.Errorf("empty response (status %d): %s", resp.StatusCode, string(body))
	}
	return &dcr, err
}

func CheckTime(expiresOn string) bool {
	seconds, err := strconv.ParseInt(expiresOn, 10, 64)
	if err != nil {
		fmt.Println("Error parsing string:", err)
		return false
	}

	utcTime := time.Unix(seconds, 0).UTC()
	localTime := utcTime.Local()

	now := time.Now()
	if utcTime.After(now) {
		fmt.Println("\nAccess Token expires on UTC Time:", utcTime.Format(time.RFC1123))
		fmt.Println("Access Token expires on Local Time:", localTime.Format(time.RFC1123))
		durationLeft := utcTime.Sub(now)
		totalMinutes := int(durationLeft.Minutes())
		if totalMinutes == 60 {
			fmt.Println("Exactly 1 hour left!!")
		} else if totalMinutes > 60 {
			fmt.Printf("%d hours and %d minutes left!!\n\n", totalMinutes/60, totalMinutes%60)
		} else {
			fmt.Printf("%d minutes left!!\n\n", totalMinutes)
		}
		return true

	} else {
		fmt.Println("\nAccess Token expired on UTC Time:", utcTime.Format(time.RFC1123))
		fmt.Println("Access Token expired on Local Time:", localTime.Format(time.RFC1123))
		return false
	}
}

func PollForToken(deviceCode string, clientID string, tenantID string, interval int, socks int) (*TokenResponse, error) {
	tokenURL := "https://login.microsoftonline.com/" + tenantID + "/oauth2/token?api-version=1.0"
	for {
		var tr TokenResponse
		client := newHttpClient(socks)
		time.Sleep(time.Duration(interval) * time.Second)
		resp, err := client.PostForm(tokenURL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":  {clientID},
			"code":       {deviceCode},
		})
		if err != nil {
			return &tr, err // ← must return here
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(body, &tr)
		switch tr.Error {
		case "":
			//fmt.Println(string(body))
			fmt.Print("\nAuthentication Success! \n\n")
			err2 := os.WriteFile(authFile, []byte(string(body)), 0600)
			fmt.Print("\nTokens written to file .fromA2Z_auth\n")
			if err2 != nil {
				fmt.Println("Error writing tokens", err2)
				return &tr, err2
			}
			return &tr, nil
		case "authorization_pending":
			fmt.Println("waiting for authentication . . .")
			continue
		case "slow_down":
			interval += 5
		default:
			return &tr, err
		}
	}
}

func ClientSecretAuth(clientID string, clientSecret string, tenantID string, scope string, socks int, silent bool) (*TokenResponse, error) {
	authority := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	client := newHttpClient(socks)
	resp, err := client.PostForm(authority, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {scope},
	})
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("empty token response (status %d): %s", resp.StatusCode, string(body))
	}
	err = os.WriteFile(authFile, body, 0600)
	if err != nil {
		fmt.Println("Error writing tokens", err)
		return &tr, err
	}
	fmt.Print("\nTokens written to file .fromA2Z_auth\n")
	noPermissions := false
	printTokenPermissions(tr.AccessToken, &noPermissions)
	if noPermissions && !silent {
		fmt.Print("No permissions found, try all scopes? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "y" {
			TryAllScopes(clientID, clientSecret, tenantID, socks)
		}
	}
	return &tr, nil
}

func printTokenPermissions(accessToken string, permissions *bool) {
	// decode the payload (middle part of JWT)
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		fmt.Println("Invalid token format")
		return
	}

	// add padding if needed
	payload := parts[1]
	for len(payload)%4 != 0 {
		payload += "="
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}

	var claims JWT
	if err := json.Unmarshal(decoded, &claims); err != nil {
		fmt.Println("Error parsing token claims:", err)
		return
	}

	fmt.Println("\n--- Token Permissions ---")
	fmt.Println("App Display Name: ", claims.ClientIdName)
	fmt.Println("App ID:           ", claims.ClientId)
	fmt.Println("Object ID:        ", claims.Oid)
	fmt.Println("Tenant ID:        ", claims.TID)

	if claims.Scope != "" {
		fmt.Println("\nDelegated Permissions (scp):")
		for _, p := range strings.Split(claims.Scope, " ") {
			fmt.Println("  -", p)
		}
	}

	if len(claims.Roles) > 0 {
		fmt.Println("\nApplication Permissions (roles):")
		for _, r := range claims.Roles {
			fmt.Println("  -", r)
		}
	}

	if claims.Scope == "" && len(claims.Roles) == 0 {
		fmt.Println("No permissions found in token")
		*permissions = true
	}

	fmt.Println("-------------------------")
}

func TryAllScopes(clientID string, clientSecret string, tenantID string, socks int) {
	scopes := []string{
		"https://graph.microsoft.com/.default",
		"https://management.azure.com/.default",
		"https://vault.azure.net/.default",
		"https://storage.azure.com/.default",
		"https://database.windows.net/.default",
		"https://outlook.office.com/.default",
		"https://outlook.office365.com/.default",
		"https://api.spaces.skype.com/.default",
		"https://msmamservice.api.application/.default",
		"https://webshell.suite.office.com/.default",
		"https://teams.microsoft.com/.default",
		"https://api.businesscentral.dynamics.com/.default",
		"https://service.powerapps.com/.default",
		"https://analysis.windows.net/powerbi/api/.default",
		"https://digitaltwins.azure.net/.default",
		"https://dev.azuresynapse.net/.default",
		"https://quantum.microsoft.com/.default",
	}

	fmt.Println("\nTrying all scopes...")
	for _, scope := range scopes {
		fmt.Printf("\n[*] Trying scope: %s\n", scope)
		tr, err := ClientSecretAuth(clientID, clientSecret, tenantID, scope, socks, true)
		if err != nil {
			fmt.Printf("    [-] Failed: %s\n", err)
			continue
		}
		if tr.AccessToken == "" {
			fmt.Println("    [-] No token returned")
			continue
		}
		noPermissions := false
		printTokenPermissions(tr.AccessToken, &noPermissions)
	}
	fmt.Println("\nDone trying all scopes.")
}

func RefreshToken(clientID string, scope string, socks int) error {
	if _, err := os.Stat(authFile); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no auth file found, please authenticate first")
	}

	data, err := os.ReadFile(authFile)
	if err != nil {
		return fmt.Errorf("error reading auth file: %w", err)
	}

	var authTokens TokenResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &authTokens); err != nil {
		return fmt.Errorf("auth file corrupted: %w", err)
	}

	if authTokens.RefreshToken == "" {
		return fmt.Errorf("no refresh token found - re-authenticate using device code or provide refresh token")
	}

	// need client id from the token
	parts := strings.Split(authTokens.AccessToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("error decoding token: %w", err)
	}

	var claims JWT
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return fmt.Errorf("error parsing token claims: %w", err)
	}

	client := newHttpClient(socks)
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", claims.TID)

	resp, err := client.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {authTokens.RefreshToken},
		"scope":         {scope},
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("error parsing response: %w", err)
	}

	if tr.AccessToken == "" {
		return fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	if err := os.WriteFile(authFile, body, 0600); err != nil {
		return fmt.Errorf("error writing auth file: %w", err)
	}

	fmt.Println("Token refreshed successfully")
	noPermissions := false
	printTokenPermissions(tr.AccessToken, &noPermissions)

	return nil
}

func RefreshTokenWithToken(refreshToken string, clientID string, tenantID string, scope string, socks int) error {
	client := newHttpClient(socks)
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	resp, err := client.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
		"scope":         {scope},
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("error parsing response: %w", err)
	}

	if tr.AccessToken == "" {
		return fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	if err := os.WriteFile(authFile, body, 0600); err != nil {
		return fmt.Errorf("error writing auth file: %w", err)
	}

	fmt.Println("Token refreshed successfully")
	noPermissions := false
	printTokenPermissions(tr.AccessToken, &noPermissions)

	return nil
}
