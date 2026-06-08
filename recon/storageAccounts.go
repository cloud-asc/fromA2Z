package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func FindStorageBlobs(access_token string, socks int) {
	client := newHttpClient(socks)

	fmt.Println("[*] Getting subscriptions...")
	req, err := http.NewRequest("GET", "https://management.azure.com/subscriptions?api-version=2020-01-01", nil)
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

	var subResult struct {
		Value []struct {
			SubscriptionId string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &subResult); err != nil {
		fmt.Println("Error parsing subscriptions:", err)
		return
	}

	fmt.Printf("[+] Found %d subscriptions\n", len(subResult.Value))

	for _, sub := range subResult.Value {
		fmt.Printf("\n[*] Checking subscription: %s (%s)\n", sub.DisplayName, sub.SubscriptionId)

		storageUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01", sub.SubscriptionId)
		req, err := http.NewRequest("GET", storageUrl, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+access_token)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		var storageResult struct {
			Value []struct {
				Name          string `json:"name"`
				ResourceGroup string `json:"id"`
				Properties    struct {
					PrimaryEndpoints struct {
						Blob string `json:"blob"`
					} `json:"primaryEndpoints"`
					AllowBlobPublicAccess bool `json:"allowBlobPublicAccess"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &storageResult); err != nil {
			fmt.Println("Error parsing storage accounts:", err)
			continue
		}

		fmt.Printf("[+] Found %d storage accounts\n", len(storageResult.Value))

		for _, account := range storageResult.Value {
			fmt.Printf("\n    [*] Storage Account: %s\n", account.Name)
			fmt.Printf("        Blob Endpoint:          %s\n", account.Properties.PrimaryEndpoints.Blob)
			fmt.Printf("        Public Access Allowed:  %v\n", account.Properties.AllowBlobPublicAccess)

			idParts := strings.Split(account.ResourceGroup, "/")
			resourceGroup := ""
			for i, part := range idParts {
				if part == "resourceGroups" && i+1 < len(idParts) {
					resourceGroup = idParts[i+1]
					break
				}
			}

			listContainersUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers?api-version=2021-09-01",
				sub.SubscriptionId, resourceGroup, account.Name)
			req, err := http.NewRequest("GET", listContainersUrl, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+access_token)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			var containerResult struct {
				Value []struct {
					Name       string `json:"name"`
					Properties struct {
						PublicAccess string `json:"publicAccess"`
					} `json:"properties"`
				} `json:"value"`
			}
			if err := json.Unmarshal(body, &containerResult); err != nil {
				continue
			}

			for _, container := range containerResult.Value {
				publicAccess := container.Properties.PublicAccess
				isPublic := publicAccess == "Blob" || publicAccess == "Container"

				if isPublic {
					fmt.Printf("\n        [!] PUBLIC Container: %s (access: %s)\n", container.Name, publicAccess)
					fmt.Printf("            URL: https://%s.blob.core.windows.net/%s\n", account.Name, container.Name)
				} else {
					fmt.Printf("\n        [+] Container: %s (access: private)\n", container.Name)
				}

				// list blobs for both public and private containers
				blobListUrl := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&include=metadata",
					account.Name, container.Name)
				blobReq, err := http.NewRequest("GET", blobListUrl, nil)
				if err != nil {
					continue
				}
				blobReq.Header.Set("Authorization", "Bearer "+access_token)
				blobReq.Header.Set("x-ms-version", "2020-10-02")

				blobResp, err := client.Do(blobReq)
				if err != nil {
					continue
				}
				blobResp.Body.Close()

				if blobResp.StatusCode == 403 {
					fmt.Println("            [!] Access denied - refresh to storage scope:")
					fmt.Println("                ./fromA2Z auth -refresh -scope \"https://storage.azure.com/.default\"")
					continue
				}

			}
		}
	}
}
