package main

import (
	"flag"
	"fmt"
	"fromA2Z/auth"
	"fromA2Z/recon"
	"os"
)

const authFile string = ".fromA2Z_auth"

func main() {

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	//reconCmd := flag.NewFlagSet("recon", flag.ExitOnError)
	//testCmd := flag.NewFlagSet("test", flag.ExitOnError)
	var clientID string
	var tenantID string
	var helpAsked bool
	var checkAsked bool
	var access_token string
	var servicePrincipal string
	var searchString string
	var sharepointLimit int
	var socks int
	var clientSecret string
	var refreshAsked bool
	var refresh_token string
	var auID string
	var userID string
	var password string
	var list bool
	var addUser string
	var resetPassword bool
	var mailFrom string
	var mailTo string
	var mailSubject string
	var mailBody string
	var appObjectId string
	reconCmd := flag.NewFlagSet("", flag.ExitOnError)
	reconCmd.StringVar(&access_token, "a", "", "AccessToken")
	reconCmd.StringVar(&servicePrincipal, "sp", "", "Service Principal ID")
	reconCmd.StringVar(&searchString, "search", "password", "Sharepoint Search String")
	reconCmd.IntVar(&socks, "socks", 69, "SOCKS5 proxy (socks5://127.0.0.1:1080)")
	reconCmd.IntVar(&sharepointLimit, "n", 10, "Search limit for Sharepoint")
	reconCmd.StringVar(&auID, "au", "", "Administrative Unit ID")
	reconCmd.StringVar(&userID, "user", "", "User ID or UPN")
	reconCmd.StringVar(&addUser, "addUser", "", "Add user to AU (provide user ID)")
	reconCmd.StringVar(&password, "password", "", "New password (optional, auto-generated if omitted)")
	reconCmd.BoolVar(&resetPassword, "resetPassword", false, "Reset password of user in AU")
	reconCmd.BoolVar(&list, "list", false, "List AUs, members, and scoped role members")
	reconCmd.StringVar(&mailFrom, "from", "", "Sender email address")
	reconCmd.StringVar(&mailTo, "to", "", "Recipient email address")
	reconCmd.StringVar(&mailSubject, "subject", "", "Email subject")
	reconCmd.StringVar(&mailBody, "body", "", "Email body (HTML supported)")
	reconCmd.StringVar(&appObjectId, "app-id", "", "App Registration Object ID to target")
	authCmd.StringVar(&clientID, "client-id", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Client ID, default value is for AZ Office Applications")
	authCmd.StringVar(&clientID, "c", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "Client ID, default value is for AZ Office Applications")
	authCmd.StringVar(&tenantID, "tenant-id", "", "Tenant ID GUID or Tenant Name (bui.com)")
	authCmd.StringVar(&tenantID, "t", "", "Tenant ID GUID or Tenant Name (bui.com)")
	authCmd.StringVar(&clientSecret, "client-secret", "", "Client Secret if using client credentials flow")
	authCmd.BoolVar(&refreshAsked, "refresh", false, "Refresh access token using refresh token")
	authCmd.StringVar(&refresh_token, "r", "", "Refresh token for authentication")
	authCmd.IntVar(&socks, "socks", 69, "SOCKS5 proxy port")
	deviceCodeAuthEnabled := authCmd.Bool("device-code-auth", false, "Device Code Auth")
	authCmd.BoolVar(&checkAsked, "check", false, "Check if authentication and also write to token file")
	authCmd.BoolVar(&helpAsked, "help", false, "Help menu")
	authCmd.BoolVar(&helpAsked, "h", false, "Help menu")
	reconCmd.BoolVar(&helpAsked, "help", false, "Help menu")
	reconCmd.BoolVar(&helpAsked, "h", false, "Help menu")
	scope := authCmd.String("scope", "https://graph.microsoft.com/.default", "Scope (graph, azure management)")
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	//resource := "https://graph.microsoft.com"
	// Must call Parse() before using any flags

	switch os.Args[1] {
	case "help":
		printUsage()
	case "h":
		printUsage()
	case "-help":
		printUsage()
	case "-h":
		printUsage()
	case "auth":
		authCmd.Parse(os.Args[2:])
		if helpAsked {
			printAuthUsage()
			return
		}

		if refreshAsked {
			if refresh_token != "" {
				if tenantID == "" {
					fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
					return
				}
				if err := auth.RefreshTokenWithToken(refresh_token, clientID, tenantID, *scope, socks); err != nil {
					fmt.Fprintln(os.Stderr, "Refresh failed:", err)
					return
				}
			}
			if err := auth.RefreshToken(clientID, *scope, socks); err != nil {
				fmt.Fprintln(os.Stderr, "Refresh failed:", err)
				return
			}
		}
		if refresh_token != "" {
			if tenantID == "" {
				fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
				return
			}
			if err := auth.RefreshTokenWithToken(refresh_token, clientID, tenantID, *scope, socks); err != nil {
				fmt.Fprintln(os.Stderr, "Refresh failed:", err)
				return
			}
		}
		if clientSecret != "" {
			tr, err := auth.ClientSecretAuth(clientID, clientSecret, tenantID, *scope, socks, false)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Client secret auth failed:", err)
				return
			}
			_ = tr
		}
		if *deviceCodeAuthEnabled {
			if tenantID == "" {
				fmt.Fprintln(os.Stderr, "error: --tenant-id is required")
				return
			}
			dc, err := auth.RequestDeviceCode(clientID, tenantID, *scope, socks)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Device code auth failed", err)
				return
			}
			fmt.Printf("\nAuthentication attempt initiated, please follow the instructions below to acquire the necessary tokens\n\n")
			fmt.Print(dc.Message, "\n\n")
			tr, err := auth.PollForToken(dc.DeviceCode, clientID, tenantID, 3, socks)
			if err != nil {
				fmt.Println("Polling failed")
			}
			auth.CheckTime(tr.ExpiresOn)
		}
		if checkAsked {
			auth.CheckAuth()
		}
		if !checkAsked && !helpAsked && !*deviceCodeAuthEnabled && !refreshAsked && clientSecret == "" {
			printAuthUsage()
			return
		}
	case "servicePrincipals":
		fmt.Println("Finding dangerous service princiapls")
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindDangerousServicePrincipals(access_token, servicePrincipal, socks)
	case "sharePoint":
		reconCmd.Parse(os.Args[2:])
		if helpAsked {
			fmt.Println("Usage: -search \"password Filetype.ps1\" -n <number of hosts> ")
			fmt.Println("Search function will give you the option to download the files as well")
			return
		}
		checkAuthForRecon(&access_token)

		recon.SearchSharePoint(access_token, searchString, sharepointLimit, socks)
	case "storage":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindStorageBlobs(access_token, socks)
	case "conditionalAccess":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.GetConditionalAccessPolicies(access_token, socks)
	case "dynamicGroups":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindDynamicGroups(access_token, socks)
	case "applications":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindDangerousApplications(access_token, appObjectId, socks)
	case "ARMDeployments":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindARMDeploymentSecrets(access_token, socks)
	case "pwned":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.FindPwnedObjects(access_token, socks)
	case "sendMail":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		if mailTo == "" || mailSubject == "" {
			fmt.Println("Usage: fromA2Z sendMail -from <email> -to <email> -subject <subject> -body <body> -a <token>")
			return
		}
		if err := recon.SendMail(access_token, mailFrom, mailTo, mailSubject, mailBody, socks); err != nil {
			fmt.Fprintln(os.Stderr, "Send mail failed:", err)
		}
	case "administrativeUnits":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)

		switch {
		case list:
			recon.ListAdministrativeUnits(access_token, socks)
		case addUser != "":
			recon.AddUserToAU(access_token, auID, addUser, socks)
		case resetPassword:
			recon.ResetUserPassword(access_token, auID, userID, password, socks)
		default:
			fmt.Println("Usage: administrativeUnits [-list] [-addUser <userID> -au <auID>] [-resetPassword -au <auID> -user <userID> [-password <pw>]]")
		}
	case "whoami":
		reconCmd.Parse(os.Args[2:])
		checkAuthForRecon(&access_token)
		recon.GetCurrentUser(access_token, socks)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		return
	}
}

func checkAuthForRecon(access_token *string) {
	if *access_token == "" {
		if !auth.CheckAuth() {
			fmt.Println("Please run auth -device-code-auth or provide access token using -a")
			return
		}
		*access_token = auth.GetAccessToken()
	}
}

func printUsage() {
	fmt.Println("\nUsage: fromA2Z <command> [arguments]")
	fmt.Println("\nAvailable commands:")
	fmt.Println("  auth    - Authenticate to the service or refresh tokens")
	fmt.Println(". pwned - Check for everything that your user owns")
	fmt.Println("  servicePrincipals   - Check service principals with dangerous permissions")
	fmt.Println("  sharePoint - Search Sharepoint")
	fmt.Println("  storage - Check storage accounts for any containers or blobs with anonymous access")
	fmt.Println("  dynamicGroups - Check all dynamic groups and their rules")
	fmt.Println("  conditionalAccess - Check contiional access policies")
	fmt.Println("  ARMDeployments - Check ARM deployments for any sensitive items")
	fmt.Println("  administrativeUnits - See any administrative units and add users if you have access")
	fmt.Println("  sendMail - If an application has the Mail.Send permission")

}

func printAuthUsage() {
	fmt.Println("\n	-check		    Check if current authentication file (.fromA2Z_auth) works")
	fmt.Println("	                    or if provided access token/refresh token works")
	fmt.Println("	-client-id          Client-ID                  ")
	fmt.Println("	-c                  ")
	fmt.Println("	-scope              Scope (graph, azure management)  ")
	fmt.Println("	-device-code-auth   Device Code Auth")
	fmt.Println("	-tenant-id          Tenant ID (required with device code auth!)")
	fmt.Println("	-t                  ")
	fmt.Println("	-access-token       Access Token")
	fmt.Println("	-a")
	fmt.Println("	-refresh-token      Refresh Token")
	fmt.Println("	-r")
	fmt.Println("	-refresh            Refresh using auth file")

	fmt.Println("	-help               Help Menu")
	fmt.Println("	-h                  ")
}
