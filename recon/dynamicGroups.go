package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func FindDynamicGroups(access_token string, socks int) {
	client := newHttpClient(socks)

	fmt.Println("[*] Getting dynamic groups...")

	nextLink := "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c+eq+'DynamicMembership')&$select=id,displayName,description,membershipRule,membershipRuleProcessingState,groupTypes,createdDateTime"

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
				ID                            string   `json:"id"`
				DisplayName                   string   `json:"displayName"`
				Description                   string   `json:"description"`
				MembershipRule                string   `json:"membershipRule"`
				MembershipRuleProcessingState string   `json:"membershipRuleProcessingState"`
				GroupTypes                    []string `json:"groupTypes"`
				CreatedDateTime               string   `json:"createdDateTime"`
			} `json:"value"`
			OdataNextLink string `json:"@odata.nextLink"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}

		fmt.Printf("[+] Found %d dynamic groups\n\n", len(result.Value))

		for _, group := range result.Value {
			fmt.Println("================================")
			fmt.Printf("Name:        %s\n", group.DisplayName)
			fmt.Printf("ID:          %s\n", group.ID)
			fmt.Printf("Description: %s\n", group.Description)
			fmt.Printf("Created:     %s\n", group.CreatedDateTime)
			fmt.Printf("State:       %s\n", group.MembershipRuleProcessingState)
			fmt.Printf("Rule:        %s\n", group.MembershipRule)

			// flag interesting rules
			rule := strings.ToLower(group.MembershipRule)
			if strings.Contains(rule, "user.jobtitle") {
				fmt.Println("[!] Rule based on jobTitle - may be manipulable if you can edit your profile")
			}
			if strings.Contains(rule, "user.department") {
				fmt.Println("[!] Rule based on department - may be manipulable if you can edit your profile")
			}
			if strings.Contains(rule, "user.country") {
				fmt.Println("[!] Rule based on country - may be manipulable if you can edit your profile")
			}
			if strings.Contains(rule, "user.usageLocation") {
				fmt.Println("[!] Rule based on usageLocation - may be manipulable if you can edit your profile")
			}
			if strings.Contains(rule, "user.extensionattribute") {
				fmt.Println("[!] Rule based on extensionAttribute - check if you can modify these")
			}
			if group.MembershipRuleProcessingState == "Paused" {
				fmt.Println("[!] Rule processing is PAUSED - membership may be stale")
			}

			fmt.Println()
		}

		nextLink = result.OdataNextLink
	}
}
