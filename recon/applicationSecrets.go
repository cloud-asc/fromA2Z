package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func FindApplications(access_token string, socks int) {
	client := newHttpClient(socks)

	fmt.Println("[*] Enumerating App Registrations...")

	nextLink := "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,owners,passwordCredentials,keyCredentials,requiredResourceAccess"

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
					KeyID       string `json:"keyId"`
					Hint        string `json:"hint"`
				} `json:"passwordCredentials"`
				KeyCredentials []struct {
					DisplayName string `json:"displayName"`
					EndDateTime string `json:"endDateTime"`
					KeyID       string `json:"keyId"`
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

		fmt.Printf("[+] Found %d app registrations\n\n", len(result.Value))

		for _, app := range result.Value {
			fmt.Println("================================")
			fmt.Printf("Name:           %s\n", app.DisplayName)
			fmt.Printf("App ID:         %s\n", app.AppID)
			fmt.Printf("Object ID:      %s\n", app.ID)
			fmt.Printf("Created:        %s\n", app.CreatedDateTime)
			fmt.Printf("Sign-in Audience: %s\n", app.SignInAudience)

			// flag multitenant apps
			if app.SignInAudience == "AzureADMultipleOrgs" || app.SignInAudience == "AzureADandPersonalMicrosoftAccount" {
				fmt.Println("[!] MULTITENANT APP - accessible from other tenants")
			}

			// client secrets
			if len(app.PasswordCredentials) > 0 {
				fmt.Printf("\nClient Secrets (%d):\n", len(app.PasswordCredentials))
				for _, secret := range app.PasswordCredentials {
					fmt.Printf("  [+] Name: %s\n", secret.DisplayName)
					fmt.Printf("      KeyID: %s\n", secret.KeyID)
					fmt.Printf("      Hint:  %s\n", secret.Hint)
					fmt.Printf("      Expires: %s\n", secret.EndDateTime)

					// flag non-expiring or long lived secrets
					if secret.EndDateTime == "" {
						fmt.Println("      [!] NO EXPIRY SET")
					} else {
						expiry, err := time.Parse(time.RFC3339, secret.EndDateTime)
						if err == nil {
							daysLeft := time.Until(expiry).Hours() / 24
							if daysLeft > 365 {
								fmt.Printf("      [!] LONG LIVED SECRET - %.0f days remaining\n", daysLeft)
							} else if daysLeft < 0 {
								fmt.Println("      [!] SECRET EXPIRED")
							} else {
								fmt.Printf("      Days remaining: %.0f\n", daysLeft)
							}
						}
					}
				}
			} else {
				fmt.Println("\nClient Secrets: none")
			}

			// certificates
			if len(app.KeyCredentials) > 0 {
				fmt.Printf("\nCertificates (%d):\n", len(app.KeyCredentials))
				for _, cert := range app.KeyCredentials {
					fmt.Printf("  [+] Name: %s\n", cert.DisplayName)
					fmt.Printf("      Type: %s\n", cert.Type)
					fmt.Printf("      KeyID: %s\n", cert.KeyID)
					fmt.Printf("      Expires: %s\n", cert.EndDateTime)
				}
			} else {
				fmt.Println("Certificates: none")
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
							fmt.Println("\nOwners: none [!] No owners - anyone with Application Admin can manage")
						} else {
							fmt.Printf("\nOwners (%d):\n", len(ownersResult.Value))
							for _, owner := range ownersResult.Value {
								fmt.Printf("  [+] %s (%s)\n", owner.DisplayName, owner.UserPrincipalName)
								if owner.OdataType == "#microsoft.graph.user" {
									fmt.Println("      [!] Owned by regular user - they can add secrets")
								}
							}
						}
					}
				}
			}

			// required permissions
			if len(app.RequiredResourceAccess) > 0 {
				fmt.Printf("\nRequested Permissions (%d resources):\n", len(app.RequiredResourceAccess))
				for _, resource := range app.RequiredResourceAccess {
					fmt.Printf("  Resource: %s\n", resource.ResourceAppID)
					for _, access := range resource.ResourceAccess {
						permType := "Delegated"
						if access.Type == "Role" {
							permType = "Application"
						}
						fmt.Printf("    [+] %s: %s\n", permType, access.ID)
					}
				}
			}

			fmt.Println()
		}

		nextLink = result.OdataNextLink
	}
}
