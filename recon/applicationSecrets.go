package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func FindDangerousApplications(access_token string, appObjectId string, socks int) {
	client := newHttpClient(socks)

	dangerousPermissions := map[string]string{
		"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
		"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
		"741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
		"c529cfca-c91b-489c-af2b-d92990b66ce6": "User.ManageIdentities.All",
		"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
		"19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
		"292d869f-3427-49a8-9dab-8c70152b74e9": "Organization.ReadWrite.All",
		"29c18626-4985-4dcd-85c0-193eef327366": "Policy.ReadWrite.AuthenticationMethod",
		"01c0a623-fc9b-48e9-b794-0756f8e8f067": "Policy.ReadWrite.ConditionalAccess",
		"50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
		"810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
		"b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
		"e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
		"6931bccd-447a-43d1-b442-00a195474933": "MailboxSettings.ReadWrite",
		"75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
		"01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All",
		"332a536c-c7ef-4017-ab91-336970924f0d": "Sites.Read.All",
		"9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
		"0c0bf378-bf22-4481-8f81-9e89a9b4960a": "Sites.Manage.All",
		"a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
		"3aeca27b-ee3a-4c2b-8ded-80376e2134a4": "Notes.Read.All",
		"0c458cef-11f3-48c2-a568-c66751c238c0": "Notes.ReadWrite.All",
		"9241abd9-d0e6-425a-bd4f-47ba86e767a4": "DeviceManagementConfiguration.ReadWrite.All",
	}

	fmt.Println("[*] Finding dangerous app registrations...")

	var nextLink string
	if appObjectId != "" {
		nextLink = fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s", appObjectId)
	} else {
		nextLink = "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess"
	}
	for nextLink != "" {
		req, err := http.NewRequest("GET", nextLink, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+access_token)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			ForbiddenSuggestion()
			return
		}

		if len(body) == 0 {
			fmt.Println("Empty response")
			return
		}

		var result struct {
			Value []struct {
				ID                  string `json:"id"`
				AppID               string `json:"appId"`
				DisplayName         string `json:"displayName"`
				CreatedDateTime     string `json:"createdDateTime"`
				SignInAudience      string `json:"signInAudience"`
				PasswordCredentials []struct {
					DisplayName string `json:"displayName"`
					EndDateTime string `json:"endDateTime"`
					Hint        string `json:"hint"`
					KeyID       string `json:"keyId"`
				} `json:"passwordCredentials"`
				KeyCredentials []struct {
					DisplayName string `json:"displayName"`
					EndDateTime string `json:"endDateTime"`
					Type        string `json:"type"`
				} `json:"keyCredentials"`
				RequiredResourceAccess []struct {
					ResourceAppID  string `json:"resourceAppId"`
					ResourceAccess []struct {
						ID   string `json:"id"`
						Type string `json:"type"`
					} `json:"resourceAccess"`
				} `json:"requiredResourceAccess"`
			} `json:"value"`
			OdataNextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		for _, app := range result.Value {
			hasDangerousPermission := false
			var foundPermissions []string

			// check requested permissions
			for _, resource := range app.RequiredResourceAccess {
				for _, access := range resource.ResourceAccess {
					if permName, exists := dangerousPermissions[access.ID]; exists {
						hasDangerousPermission = true
						permType := "Delegated"
						if access.Type == "Role" {
							permType = "Application"
						}
						foundPermissions = append(foundPermissions, fmt.Sprintf("%s (%s)", permName, permType))
					}
				}
			}

			if !hasDangerousPermission {
				continue
			}

			fmt.Println("================================")
			fmt.Printf("Name:     %s\n", app.DisplayName)
			fmt.Printf("App ID:   %s\n", app.AppID)
			fmt.Printf("Object ID: %s\n", app.ID)
			fmt.Printf("Created:  %s\n", app.CreatedDateTime)

			// flag multitenant
			if app.SignInAudience == "AzureADMultipleOrgs" || app.SignInAudience == "AzureADandPersonalMicrosoftAccount" {
				fmt.Printf("[!] MULTITENANT - accessible from other tenants (audience: %s)\n", app.SignInAudience)
			}

			// dangerous permissions
			fmt.Printf("\nDangerous Permissions (%d):\n", len(foundPermissions))
			for _, p := range foundPermissions {
				fmt.Printf("  [!] %s\n", p)
			}

			// secrets
			if len(app.PasswordCredentials) > 0 {
				fmt.Printf("\nClient Secrets (%d):\n", len(app.PasswordCredentials))
				for _, secret := range app.PasswordCredentials {
					fmt.Printf("  [+] %s (hint: %s)\n", secret.DisplayName, secret.Hint)
					fmt.Printf("      Expires: %s\n", secret.EndDateTime)
					if secret.EndDateTime != "" {
						expiry, err := time.Parse(time.RFC3339, secret.EndDateTime)
						if err == nil {
							daysLeft := time.Until(expiry).Hours() / 24
							if daysLeft > 365 {
								fmt.Printf("      [!] Long lived - %.0f days remaining\n", daysLeft)
							} else if daysLeft < 0 {
								fmt.Println("      [!] EXPIRED")
							}
						}
					}
				}
			} else {
				fmt.Println("\nClient Secrets: none")
			}

			// certs
			if len(app.KeyCredentials) > 0 {
				fmt.Printf("\nCertificates (%d):\n", len(app.KeyCredentials))
				for _, cert := range app.KeyCredentials {
					fmt.Printf("  [+] %s (type: %s) expires: %s\n", cert.DisplayName, cert.Type, cert.EndDateTime)
				}
			}

			// owners
			ownersUrl := fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s/owners", app.ID)
			ownersReq, err := http.NewRequest("GET", ownersUrl, nil)
			if err == nil {
				ownersReq.Header.Set("Authorization", "Bearer "+access_token)
				ownersResp, err := client.Do(ownersReq)
				if err == nil {
					ownersBody, _ := io.ReadAll(ownersResp.Body)
					ownersResp.Body.Close()

					var ownersResult struct {
						Value []struct {
							DisplayName       string `json:"displayName"`
							UserPrincipalName string `json:"userPrincipalName"`
							OdataType         string `json:"@odata.type"`
						} `json:"value"`
					}
					if err := json.Unmarshal(ownersBody, &ownersResult); err == nil {
						if len(ownersResult.Value) == 0 {
							fmt.Println("\nOwners: none [!] anyone with Application Admin can manage this")
						} else {
							fmt.Printf("\nOwners (%d):\n", len(ownersResult.Value))
							for _, owner := range ownersResult.Value {
								fmt.Printf("  [+] %s (%s)\n", owner.DisplayName, owner.UserPrincipalName)
								if owner.OdataType == "#microsoft.graph.user" {
									fmt.Println("      [!] Regular user owner - can add secrets and authenticate as this app")
								}
							}
						}
					}
				}
			}

			fmt.Println()
		}

		nextLink = result.OdataNextLink
	}
}
