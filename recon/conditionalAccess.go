package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func GetConditionalAccessPolicies(access_token string, socks int) {
	client := newHttpClient(socks)

	fmt.Println("[*] Getting Conditional Access Policies...")
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", nil)
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
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"`
			Conditions  struct {
				Users struct {
					IncludeUsers  []string `json:"includeUsers"`
					ExcludeUsers  []string `json:"excludeUsers"`
					IncludeGroups []string `json:"includeGroups"`
					ExcludeGroups []string `json:"excludeGroups"`
					IncludeRoles  []string `json:"includeRoles"`
					ExcludeRoles  []string `json:"excludeRoles"`
				} `json:"users"`
				Applications struct {
					IncludeApplications []string `json:"includeApplications"`
					ExcludeApplications []string `json:"excludeApplications"`
				} `json:"applications"`
				Platforms struct {
					IncludePlatforms []string `json:"includePlatforms"`
					ExcludePlatforms []string `json:"excludePlatforms"`
				} `json:"platforms"`
				Locations struct {
					IncludeLocations []string `json:"includeLocations"`
					ExcludeLocations []string `json:"excludeLocations"`
				} `json:"locations"`
				SignInRiskLevels []string `json:"signInRiskLevels"`
				UserRiskLevels   []string `json:"userRiskLevels"`
			} `json:"conditions"`
			GrantControls struct {
				Operator        string   `json:"operator"`
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
			SessionControls struct {
				SignInFrequency struct {
					Value     int    `json:"value"`
					Type      string `json:"type"`
					IsEnabled bool   `json:"isEnabled"`
				} `json:"signInFrequency"`
				PersistentBrowser struct {
					Mode      string `json:"mode"`
					IsEnabled bool   `json:"isEnabled"`
				} `json:"persistentBrowser"`
			} `json:"sessionControls"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Error parsing response:", err)
		return
	}

	fmt.Printf("[+] Found %d Conditional Access Policies\n\n", len(result.Value))

	for _, policy := range result.Value {
		fmt.Printf("================================\n")
		fmt.Printf("Name:  %s\n", policy.DisplayName)
		fmt.Printf("ID:    %s\n", policy.ID)
		fmt.Printf("State: %s\n", policy.State)

		// flag disabled policies
		if policy.State == "disabled" {
			fmt.Println("[!] POLICY IS DISABLED")
		}

		// users
		fmt.Println("\nUsers:")
		fmt.Printf("  Include: %v\n", policy.Conditions.Users.IncludeUsers)
		fmt.Printf("  Exclude: %v\n", policy.Conditions.Users.ExcludeUsers)
		fmt.Printf("  Include Groups: %v\n", policy.Conditions.Users.IncludeGroups)
		fmt.Printf("  Exclude Groups: %v\n", policy.Conditions.Users.ExcludeGroups)
		fmt.Printf("  Include Roles: %v\n", policy.Conditions.Users.IncludeRoles)
		fmt.Printf("  Exclude Roles: %v\n", policy.Conditions.Users.ExcludeRoles)

		// applications
		fmt.Println("\nApplications:")
		fmt.Printf("  Include: %v\n", policy.Conditions.Applications.IncludeApplications)
		fmt.Printf("  Exclude: %v\n", policy.Conditions.Applications.ExcludeApplications)

		// platforms
		if len(policy.Conditions.Platforms.IncludePlatforms) > 0 {
			fmt.Println("\nPlatforms:")
			fmt.Printf("  Include: %v\n", policy.Conditions.Platforms.IncludePlatforms)
			fmt.Printf("  Exclude: %v\n", policy.Conditions.Platforms.ExcludePlatforms)
		}

		// locations
		if len(policy.Conditions.Locations.IncludeLocations) > 0 {
			fmt.Println("\nLocations:")
			fmt.Printf("  Include: %v\n", policy.Conditions.Locations.IncludeLocations)
			fmt.Printf("  Exclude: %v\n", policy.Conditions.Locations.ExcludeLocations)
		}

		// risk levels
		if len(policy.Conditions.SignInRiskLevels) > 0 {
			fmt.Printf("\nSign-in Risk Levels: %v\n", policy.Conditions.SignInRiskLevels)
		}
		if len(policy.Conditions.UserRiskLevels) > 0 {
			fmt.Printf("User Risk Levels: %v\n", policy.Conditions.UserRiskLevels)
		}

		// grant controls
		if policy.GrantControls.Operator != "" {
			fmt.Println("\nGrant Controls:")
			fmt.Printf("  Operator: %s\n", policy.GrantControls.Operator)
			fmt.Printf("  Controls: %v\n", policy.GrantControls.BuiltInControls)

			// flag if no MFA required
			hasMFA := false
			for _, control := range policy.GrantControls.BuiltInControls {
				if control == "mfa" {
					hasMFA = true
				}
			}
			if !hasMFA {
				fmt.Println("  [!] NO MFA REQUIRED")
			}
		}

		// session controls
		if policy.SessionControls.SignInFrequency.IsEnabled {
			fmt.Printf("\nSign-in Frequency: %d %s\n",
				policy.SessionControls.SignInFrequency.Value,
				policy.SessionControls.SignInFrequency.Type)
		}
		if policy.SessionControls.PersistentBrowser.IsEnabled {
			fmt.Printf("Persistent Browser: %s\n", policy.SessionControls.PersistentBrowser.Mode)
		}

		fmt.Println()
	}
}
