
    $applicationId  = '45920d58-e4ca-4a55-a6f0-eacf6fccef47'
    $tenantId       = '5f36d76e-9089-4ef3-94fc-d1758088e39a'
    $certThumbprint = '94B1E1FDD9B986BF00B81650809D0A013EF40F9A'

    Connect-MgGraph -CertificateThumbprint $certThumbprint -ClientID $applicationId -TenantId $tenantId

    Connect-AzAccount -ApplicationId $applicationId -Tenant $tenantId -CertificateThumbprint $certThumbprint
    Connect-AzAccount -ServicePrincipal -ApplicationId $applicationId -Tenant $tenantId -CertificateThumbprint $certThumbprint





$tenant_id = "5f36d76e-9089-4ef3-94fc-d1758088e39a"
$client_id = "bd72e750-c7dc-42c3-a12f-d8a8c6bb0903"
$client_secret = [System.Web.HttpUtility]::UrlEncode("DGiFW7i4_yN0~R0~91KGcbjqU3~_hS6vR2")
$resource = 'https://arcadespizzilab.onmicrosoft.com/powershell-automation'

$uri = "https://login.microsoftonline.com/$tenant_id/oauth2/token?grant_type=client_credentials&resource=$resource&client_id=$client_id&client_secret=$client_secret"
Invoke-RestMethod -Method 'Get' -ContentType 'application/x-www-form-urlencoded' -Uri $uri

#




curl -X GET -H 'Content-Type: application/x-www-form-urlencoded' \
-d "grant_type=client_credentials&client_id=<client-id>&resource=<azure_databricks_resource_id>&client_secret=<application-secret>" \





$refreshToken = ""

function Get-GCITSAccessTokenByResource($AppCredential, $tenantid, $Resource) {
    $authority = "https://login.microsoftonline.com/$tenantid"
    $tokenEndpointUri = "$authority/oauth2/token"
    $content = @{
        grant_type = "refresh_token"
        client_id = $appCredential.appID
        client_secret = $appCredential.secret
        resource = $resource
        refresh_token = $appCredential.refreshToken
    }
    $tokenEndpointUri = "$authority/oauth2/token"

    $response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
    $access_token = $response.access_token
    return $access_token
}

$AppCredential = @{
    appId        = $client_id
    secret       = $client_secret
    refreshToken = $refreshToken
}

$MSGraphToken = Get-GCITSAccessTokenByResource -Resource "https://graph.microsoft.com" -tenantid $tenant_id -AppCredential $AppCredential
$AadGraphToken = Get-GCITSAccessTokenByResource -Resource "https://graph.windows.net" -tenantid $tenant_id -AppCredential $AppCredential
# Connect-AzureAD -AadAccessToken $AadGraphToken -MsAccessToken $MSGraphToken -AccountId $delegatedAdmin
