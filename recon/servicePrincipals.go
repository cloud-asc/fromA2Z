package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

const authFile string = ".fromA2Z_auth"

func FindDangerousServicePrincipals(access_token string, sp string, socks int) {
	if sp != "" {
		getDangerousPermissions(sp, "", access_token, socks)
		return
	}

	type ServicePrincipal struct {
		ID             string `json:"id"`
		AppDisplayName string `json:"appDisplayName"`
	}

	// collect all SPs first
	var allSPs []ServicePrincipal
	nextLink := "https://graph.microsoft.com/v1.0/servicePrincipals?%24filter=servicePrincipalType+eq+%27Application%27"

	for nextLink != "" {
		req, err := http.NewRequest("GET", nextLink, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+access_token)
		client := newHttpClient(socks)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			return
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Println("Error reading response:", err)
			return
		}

		if resp.StatusCode == 403 {
			ForbiddenSuggestion()
			return
		}

		var result struct {
			Value         []ServicePrincipal `json:"value"`
			OdataNextLink string             `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		allSPs = append(allSPs, result.Value...)
		nextLink = result.OdataNextLink
	}

	fmt.Printf("Found %d service principals, checking permissions...\n", len(allSPs))

	// worker pool with 10 concurrent workers
	jobs := make(chan ServicePrincipal, len(allSPs))
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for app := range jobs {
				if app.AppDisplayName != "" {
					//fmt.Printf("Checking application %s : %s\n", app.ID, app.AppDisplayName)
					getDangerousPermissions(app.ID, app.AppDisplayName, access_token, socks)
				} else {
					getDangerousPermissions(app.ID, "", access_token, socks)
				}
			}
		}()
	}

	for _, app := range allSPs {
		jobs <- app
	}
	close(jobs)
	wg.Wait()

	fmt.Println("Done.")
}

func getDangerousPermissions(servicePrincipalId string, appDisplayName string, access_token string, socks int) {
	//danger := 0
	dangerousRoles := map[string]string{
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

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments", servicePrincipalId)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := newHttpClient(socks)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	var result struct {
		Value []struct {
			AppRoleId string `json:"appRoleId"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Error parsing response:", err)
		return
	}
	for _, assignment := range result.Value {
		if permissionName, exists := dangerousRoles[assignment.AppRoleId]; exists {
			fmt.Printf("[+] Service Principal %s : %s -  %s\n",
				appDisplayName, servicePrincipalId, permissionName)
		}
	}
}

func checkServicePrincipalOwners(servicePrincipalId string, appDisplayName string, access_token string, socks int) {
	// Check owners
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/owners", servicePrincipalId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := newHttpClient(socks)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	var ownersResult struct {
		Value []struct {
			ID                string `json:"id"`
			DisplayName       string `json:"displayName"`
			OdataType         string `json:"@odata.type"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &ownersResult); err != nil {
		return
	}

	for _, owner := range ownersResult.Value {
		// flag non-admin users as owners
		fmt.Printf("owned by: %s (%s)\n", owner.DisplayName, owner.UserPrincipalName)
	}

}
