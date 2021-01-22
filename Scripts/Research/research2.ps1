[string]$ClientId = "<guid of Azure AD app id to be used for authentication>", # Azure AD client app ID
[string]$ClientSecret = "<client secret value for corresponding app id>", # Azure AD client app secret
[string]$Tenant = "<guild>", # Azure AD tenant ID
[string]$Resource = "https://<appname.domain.com>/", # Resource realm, typically something like https://app.azurewebsites.net or https://instance.crm.dynamics.com

Add-Type -AssemblyName System.Web

# Get Auth Token from AAD for App
Function Get-AuthToken
{
Param (
[String]$tenantId,
[String]$applicationId,
[String]$secret,
[string]$ApiEndpointUri
)
$encodedSecret = [System.Web.HttpUtility]::UrlEncode($secret)

$RequestAccessTokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"
$body = "grant_type=client_credentials&client_id=$applicationId&client_secret=$encodedSecret&resource=$apiEndpointUri"
$contentType = 'application/x-www-form-urlencoded'
try
{
$Token = Invoke-RestMethod -Method Post -Uri $RequestAccessTokenUri -Body $body -ContentType $contentType
$script:AuthenticationResult = Get-AuthToken -apiEndpointUri $Resource -tenantId $Tenant -applicationId $ClientId -secret $ClientSecret
}
catch { throw }
}