# FROM A 2 Z! Azure Enumeration Tool
This is a tool for everything Azure. I will be adding features as time goes on and will be regularly updating the functionality. Please let me know if there are any bugs to fix and I will be quick to fix them. The goal is to have this be an all-inclusive tool for Azure and capture almost everything from A to Z haha.

## Installation
```
//that's it!
go build fromA2Z.go
```

## Authentication
```
All authentication will be saved on file to .fromA2Z_auth

Device code auth
./fromA2Z -device-code-auth -t <tenant-id> -scope <optional> -client-id <optional>  
(The default client ID will be Microsoft office)

Refresh token
./fromA2Z -t <tenant-id> -refresh -r <refresh-token> 

Application authentication
./fromA2Z -t <tenant-id> -client-id <sp-id or app-id> -client-secret <secret>

Access token
Use the -a flag when running any recon commands to use an access token directly!
```

Tips and tricks: During your testing, try different client IDs if one is not accessibly by your user. Each client ID will give you different permissions and are focused on a particular action. You can try changing the scope to enumerate different things like Azure Management resources.

I've added three different files that you can try out and explore the functionality of each part: foci-groups.txt, useful-clientids.txt, scopes-to-test.txt

## SOCKS Compatible
This tool is socks compatible, no need to run proxychains
```
./fromA2Z action -socks 1080
```

## Reconnaissance

PWNED - Check everything that your current user context owns. 
```
./fromA2Z pwned
```

WHOAMI - Prints out your current access token and shows you the current context you are in
```
./fromA2Z whoami
```

Service Principals - Enumerate all the service principals within the tenant and see which ones have dangerous permissions
```
./fromA2Z servicePrincipals -sp <optional>
```

SharePoint enumeration - Use your graph token to search for secrets and configuration files in SharePoint. Quickly download any hits that you've found
```
./fromA2Z sharePoint -search "password Filetype:ps1" -n <max search>
```

Storage Accounts [SUBSCRIPTION REQUIRED] - Find all storage accounts that are public facing and investigate if there are any sensitive files
```
./fromA2Z storage
```

Dynamic Groups - Check if dynamic groups have any rules that would allow a user to join sensitive groups
```
./fromA2Z dynamicGroups
```

Applications - Discover applications within the tenant and see which ones have dangerous permissions and who the owners are
```
./fromA2Z applications
```

ARMDeployments [SUBSCRIPTION REQUIRED] - Check ARM Deployments to see if any sensitive information have been instilled in creating Azure resources
```
./fromA2Z ARMDeployments
```

Send Mail - If you've acquired authentication as resource that has the Mail.Send role, this will allow you to send mail as the user. Currently the /me endpoint does not work during application authentication so you must specify a -from e-mail
```
./fromA2Z sendMail -from <subject> -to <recipient> -body message -subject subject
```

Administrative Units - Check if there are any administrative units in the tenant and check which users have the User Administrator role within these units. These users will be able to reset the password for any user within the AU.
```
./fromA2Z administrativeUnits
```

## Credits
https://github.com/8ales - Marios Gyftos, my good friend, to the many Cloud CTFs we've played and won
https://github.com/dirkjanm/ROADtools - I've learned so much about Azure authentication thanks to this tool, thank you
https://github.com/dafthack/graphrunner - A tool I've used so much for SharePoint enumeration, thank you


