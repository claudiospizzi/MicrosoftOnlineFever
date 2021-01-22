[string]$ClientId = "<guid of Azure AD app id to be used for authentication>", # Azure AD client app ID
[string]$ClientSecret = "<client secret value for corresponding app id>", # Azure AD client app secret
[string]$Tenant = "<guild>", # Azure AD tenant ID
[string]$Resource = "https://<appname.domain.com>/", # Resource realm, typically something like https://app.azurewebsites.net or https://instance.crm.dynamics.com
$AuthString = "https://login.windows.net/$($tenant)"

Add-Type -Path ".\DLL\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

Function Create-Token
{
# Creates a context for login.windows.net (Azure AD common authentication)
[Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]$AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]$AuthString

# Creates a credential from the client id and key
[Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential]$ClientCredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential"($AlientID, $ClientSecret)

# Requests a bearer token
$script:AuthenticationResult = $AuthContext.AcquireTokenAsync($Resource, $ClientCredential);
}