package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	// check administrative units
	fmt.Println("\n[*] Checking Administrative Units...")

	auUrl := "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.administrativeUnit"
	auReq, err := http.NewRequest("GET", auUrl, nil)
	if err == nil {
		auReq.Header.Set("Authorization", "Bearer "+access_token)
		auResp, err := client.Do(auReq)
		if err == nil {
			auBody, _ := io.ReadAll(auResp.Body)
			auResp.Body.Close()

			var auResult struct {
				Value []struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
					Description string `json:"description"`
				} `json:"value"`
			}

			if err := json.Unmarshal(auBody, &auResult); err == nil {
				if len(auResult.Value) == 0 {
					fmt.Println("[-] No administrative units found")
				}
				for _, au := range auResult.Value {
					fmt.Printf("\n    [+] Administrative Unit: %s (%s)\n", au.DisplayName, au.ID)
					fmt.Printf("        Description: %s\n", au.Description)

					// check scoped role members
					scopedUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/scopedRoleMembers", au.ID)
					scopedReq, err := http.NewRequest("GET", scopedUrl, nil)
					if err != nil {
						continue
					}
					scopedReq.Header.Set("Authorization", "Bearer "+access_token)
					scopedResp, err := client.Do(scopedReq)
					if err != nil {
						continue
					}
					scopedBody, _ := io.ReadAll(scopedResp.Body)
					scopedResp.Body.Close()

					var scopedResult struct {
						Value []struct {
							ID             string `json:"id"`
							RoleID         string `json:"roleId"`
							RoleMemberInfo struct {
								ID          string `json:"id"`
								DisplayName string `json:"displayName"`
							} `json:"roleMemberInfo"`
						} `json:"value"`
					}

					if err := json.Unmarshal(scopedBody, &scopedResult); err == nil {
						for _, member := range scopedResult.Value {
							// get role name
							roleUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/directoryRoles/%s", member.RoleID)
							roleReq, err := http.NewRequest("GET", roleUrl, nil)
							if err != nil {
								continue
							}
							roleReq.Header.Set("Authorization", "Bearer "+access_token)
							roleResp, err := client.Do(roleReq)
							if err != nil {
								continue
							}
							roleBody, _ := io.ReadAll(roleResp.Body)
							roleResp.Body.Close()

							var role struct {
								DisplayName string `json:"displayName"`
							}
							json.Unmarshal(roleBody, &role)

							fmt.Printf("        [!] Scoped Role: %s assigned to %s\n",
								role.DisplayName, member.RoleMemberInfo.DisplayName)

							// flag dangerous roles
							roleLower := strings.ToLower(role.DisplayName)
							if strings.Contains(roleLower, "user administrator") {
								fmt.Println("            [!!!] Can reset passwords of users in this AU")
							} else if strings.Contains(roleLower, "helpdesk") {
								fmt.Println("            [!!!] Can reset passwords of non-admin users in this AU")
							} else if strings.Contains(roleLower, "groups") {
								fmt.Println("            [!] Can manage groups in this AU")
							} else if strings.Contains(roleLower, "authentication") {
								fmt.Println("            [!!!] Can manage auth methods - MFA reset")
							}
						}
					}

					// list members of the AU
					membersUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/directory/administrativeUnits/%s/members?$select=id,displayName,userPrincipalName", au.ID)
					membersReq, err := http.NewRequest("GET", membersUrl, nil)
					if err != nil {
						continue
					}
					membersReq.Header.Set("Authorization", "Bearer "+access_token)
					membersResp, err := client.Do(membersReq)
					if err != nil {
						continue
					}
					membersBody, _ := io.ReadAll(membersResp.Body)
					membersResp.Body.Close()

					var membersResult struct {
						Value []struct {
							ID                string `json:"id"`
							DisplayName       string `json:"displayName"`
							UserPrincipalName string `json:"userPrincipalName"`
						} `json:"value"`
					}

					if err := json.Unmarshal(membersBody, &membersResult); err == nil {
						fmt.Printf("        Members (%d):\n", len(membersResult.Value))
						for _, member := range membersResult.Value {
							fmt.Printf("            [+] %s (%s)\n", member.DisplayName, member.UserPrincipalName)
						}
					}
				}
			}
		}
	}
}
