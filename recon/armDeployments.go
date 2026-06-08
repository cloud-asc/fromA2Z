package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func FindARMDeploymentSecrets(access_token string, socks int) {
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

	// keywords to flag in deployment parameters
	sensitiveKeywords := []string{
		"password", "secret", "key", "token", "credential",
		"connectionstring", "apikey", "api_key", "client_secret",
		"private", "cert", "pfx", "pwd", "pass",
	}

	for _, sub := range subResult.Value {
		fmt.Printf("\n[*] Checking subscription: %s (%s)\n", sub.DisplayName, sub.SubscriptionId)

		// get resource groups
		rgUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups?api-version=2021-04-01", sub.SubscriptionId)
		req, err := http.NewRequest("GET", rgUrl, nil)
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

		var rgResult struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &rgResult); err != nil {
			continue
		}

		fmt.Printf("[+] Found %d resource groups\n", len(rgResult.Value))

		for _, rg := range rgResult.Value {
			fmt.Printf("\n    [*] Resource Group: %s\n", rg.Name)

			// get deployments in resource group
			deployUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Resources/deployments?api-version=2021-04-01",
				sub.SubscriptionId, rg.Name)

			nextLink := deployUrl
			for nextLink != "" {
				req, err := http.NewRequest("GET", nextLink, nil)
				if err != nil {
					break
				}
				req.Header.Set("Authorization", "Bearer "+access_token)

				resp, err := client.Do(req)
				if err != nil {
					break
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()

				var deployResult struct {
					Value []struct {
						ID         string `json:"id"`
						Name       string `json:"name"`
						Properties struct {
							Timestamp         string `json:"timestamp"`
							ProvisioningState string `json:"provisioningState"`
							Parameters        map[string]struct {
								Value interface{} `json:"value"`
								Type  string      `json:"type"`
							} `json:"parameters"`
						} `json:"properties"`
					} `json:"value"`
					OdataNextLink string `json:"@odata.nextLink"`
				}

				if err := json.Unmarshal(body, &deployResult); err != nil {
					break
				}

				for _, deploy := range deployResult.Value {
					fmt.Printf("\n        [+] Deployment: %s\n", deploy.Name)
					fmt.Printf("            Timestamp: %s\n", deploy.Properties.Timestamp)
					fmt.Printf("            State:     %s\n", deploy.Properties.ProvisioningState)
					fmt.Printf("            Parameters (%d):\n", len(deploy.Properties.Parameters))

					for paramName, paramValue := range deploy.Properties.Parameters {
						valueStr := fmt.Sprintf("%v", paramValue.Value)

						// check if parameter name looks sensitive
						paramLower := strings.ToLower(paramName)
						isSensitive := false
						for _, keyword := range sensitiveKeywords {
							if strings.Contains(paramLower, keyword) {
								isSensitive = true
								break
							}
						}

						if isSensitive {
							fmt.Printf("            [!] %s = %s\n", paramName, valueStr)
						} else {
							fmt.Printf("                %s = %s\n", paramName, valueStr)
						}
					}

					// also get the full deployment template which may have hardcoded values
					templateUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Resources/deployments/%s/exportTemplate?api-version=2021-04-01",
						sub.SubscriptionId, rg.Name, deploy.Name)
					templateReq, err := http.NewRequest("POST", templateUrl, nil)
					if err != nil {
						continue
					}
					templateReq.Header.Set("Authorization", "Bearer "+access_token)

					templateResp, err := client.Do(templateReq)
					if err != nil {
						continue
					}
					templateBody, _ := io.ReadAll(templateResp.Body)
					templateResp.Body.Close()

					// scan template for sensitive keywords
					templateStr := strings.ToLower(string(templateBody))
					for _, keyword := range sensitiveKeywords {
						if strings.Contains(templateStr, keyword) {
							fmt.Printf("            [!] Template contains keyword: %s\n", keyword)
						}
					}
				}

				nextLink = deployResult.OdataNextLink
			}
		}
	}
}
