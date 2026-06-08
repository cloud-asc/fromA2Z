package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func FindPwnedObjects(access_token string, socks int) {
	client := newHttpClient(socks)

	endpoints := []struct {
		URL  string
		Name string
	}{
		{"https://graph.microsoft.com/v1.0/me/ownedObjects", "Owned Objects"},
		{"https://graph.microsoft.com/v1.0/me/ownedDevices", "Owned Devices"},
		{"https://graph.microsoft.com/v1.0/me/createdObjects", "Created Objects"},
		{"https://graph.microsoft.com/v1.0/me/memberOf", "Group Memberships"},
		{"https://graph.microsoft.com/v1.0/me/transitiveMemberOf", "Transitive Group Memberships"},
	}

	for _, endpoint := range endpoints {
		fmt.Printf("\n[*] Checking %s...\n", endpoint.Name)

		nextLink := endpoint.URL
		for nextLink != "" {
			req, err := http.NewRequest("GET", nextLink, nil)
			if err != nil {
				fmt.Println("Error creating request:", err)
				break
			}
			req.Header.Set("Authorization", "Bearer "+access_token)

			resp, err := client.Do(req)
			if err != nil {
				fmt.Println("Error making request:", err)
				break
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode == 403 {
				fmt.Printf("[-] Access denied for %s\n", endpoint.Name)
				break
			}

			var result struct {
				Value []struct {
					OdataType         string   `json:"@odata.type"`
					ID                string   `json:"id"`
					DisplayName       string   `json:"displayName"`
					AppID             string   `json:"appId"`
					UserPrincipalName string   `json:"userPrincipalName"`
					GroupTypes        []string `json:"groupTypes"`
					RoleTemplateID    string   `json:"roleTemplateId"`
					Description       string   `json:"description"`
				} `json:"value"`
				OdataNextLink string `json:"@odata.nextLink"`
			}

			if err := json.Unmarshal(body, &result); err != nil {
				fmt.Println("Error parsing response:", err)
				break
			}

			fmt.Printf("[+] Found %d %s\n", len(result.Value), endpoint.Name)

			for _, obj := range result.Value {
				switch obj.OdataType {
				case "#microsoft.graph.servicePrincipal":
					fmt.Printf("\n    [!] Owned Service Principal: %s (%s)\n", obj.DisplayName, obj.ID)
					fmt.Println("        You can add secrets and authenticate as this SP")
				case "#microsoft.graph.application":
					fmt.Printf("\n    [!] Owned App Registration: %s (AppID: %s)\n", obj.DisplayName, obj.AppID)
					fmt.Println("        You can add secrets and authenticate as this app")
				case "#microsoft.graph.group":
					isDynamic := false
					for _, gt := range obj.GroupTypes {
						if gt == "DynamicMembership" {
							isDynamic = true
						}
					}
					if isDynamic {
						fmt.Printf("\n    [+] Owned Dynamic Group: %s (%s)\n", obj.DisplayName, obj.ID)
						fmt.Println("        You own this group but membership is dynamic")
					} else {
						fmt.Printf("\n    [!] Owned Group: %s (%s)\n", obj.DisplayName, obj.ID)
						fmt.Println("        You can add/remove members from this group")
					}
				case "#microsoft.graph.device":
					fmt.Printf("\n    [+] Owned Device: %s (%s)\n", obj.DisplayName, obj.ID)
				case "#microsoft.graph.directoryRole":
					fmt.Printf("\n    [!] Directory Role: %s\n", obj.DisplayName)
					fmt.Printf("        Description: %s\n", obj.Description)
				case "#microsoft.graph.administrativeUnit":
					fmt.Printf("\n    [!] Administrative Unit: %s (%s)\n", obj.DisplayName, obj.ID)
					fmt.Println("        You may have admin rights over users/groups in this AU")
				default:
					fmt.Printf("\n    [+] %s: %s (%s)\n", obj.OdataType, obj.DisplayName, obj.ID)
				}
			}

			nextLink = result.OdataNextLink
		}
	}

	// also check role assignments directly
	fmt.Println("\n[*] Checking assigned roles...")
	roleUrl := "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole"
	req, err := http.NewRequest("GET", roleUrl, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+access_token)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var roleResult struct {
				Value []struct {
					DisplayName    string `json:"displayName"`
					Description    string `json:"description"`
					RoleTemplateID string `json:"roleTemplateId"`
				} `json:"value"`
			}
			if err := json.Unmarshal(body, &roleResult); err == nil {
				if len(roleResult.Value) == 0 {
					fmt.Println("[-] No directory roles assigned")
				}
				for _, role := range roleResult.Value {
					fmt.Printf("\n    [!] Role: %s\n", role.DisplayName)
					fmt.Printf("        Description: %s\n", role.Description)
				}
			}
		}
	}
}
