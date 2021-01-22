<#
    .SYNOPSIS
        .

    .DESCRIPTION
        .

    .INPUTS
        .

    .OUTPUTS
        .

    .EXAMPLE
        PS C:\> Grant-MicrosoftOnlineAdminConsent
        .

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Grant-MicrosoftOnlineAdminConsent
{
    [CmdletBinding()]
    param
    (
        # Id of the target tenant.
        [Parameter(Mandatory = $true)]
        [System.String]
        $TenantId,

        # The client id (application id).
        [Parameter(Mandatory = $true)]
        [Alias('ApplicationId')]
        [System.String]
        $ClientId,

        $ClientId2,

        # The client secret registered in the application.
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $ClientSecret,

        # Id of the required resource access object.
        [Parameter(Mandatory = $true)]
        [System.String]
        $ResourceId,

        # Scope to grant.
        [Parameter(Mandatory = $true)]
        [System.String]
        $Scope
    )

    # Create an bearer access token for the consent grant.
    $accessTokenBody = @{
        grant_type    = "client_credentials"
        # scope         = "https://graph.microsoft.com/.default"
        scope         = "https://graph.windows.net/.default"
        client_id     = $ClientId
        client_secret = Unprotect-SecureString -SecureString $ClientSecret
    }
    $accessTokenSplat = @{
        Method = 'POST'
        Uri    = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
        Body   = $accessTokenBody
    }
    $accessToken = Invoke-RestMethod @accessTokenSplat

    # # Invoke the consent grand on the resource scope.
    # $consentGrantBody = @{
    #     clientId    = $ClientId
    #     consentType = 'AllPrincipals'
    #     principalId = $null
    #     resourceId  = $ResourceId
    #     scope       = $Scope
    #     startTime   = '{0:yyyy-MM-ddTHH:mm:ssZ}' -f [System.DateTime]::UtcNow
    #     expiryTime  = '{0:yyyy-MM-ddTHH:mm:ssZ}' -f [System.DateTime]::UtcNow
    # }
    # $consentGrantSplat = @{
    #     Method      = 'POST'
    #     Uri         = 'https://graph.microsoft.com/beta/oauth2PermissionGrants'
    #     ContentType = 'application/json'
    #     Headers     = @{ Authorization = 'Bearer {0}' -f $accessToken.access_token }
    #     Body        = $consentGrantBody | ConvertTo-Json
    # }
    # Invoke-RestMethod @consentGrantSplat

    # Invoke the consent grand on the resource scope.
    $consentGrantBody = @{
        clientAppId        = '12f9ac58-cf1a-4201-b936-f4a5e4af5ecd'  # $application.AppId
        onBehalfOfAll      = $true
        checkOnly          = $false
        tags               = @()
        constrainToRra     = $true
        dynamicPermissions = @(
            @{
                appIdentifier = '00000003-0000-0000-c000-000000000000'  # Get-AzureADApplication | % RequiredResourceAccess | % ResourceAppId
                appRoles      = @('Directory.ReadWrite.All')
                scopes        = @()
            }
            @{
                appIdentifier = '00000002-0000-0ff1-ce00-000000000000'  # Get-AzureADApplication | % RequiredResourceAccess | % ResourceAppId
                appRoles      = @('Exchange.ManageAsApp')
                scopes        = @()
            }
        )
    }
    $consentGrantSplat = @{
        Method      = 'POST'
        Uri         = 'https://graph.windows.net/myorganization/consentToApp?api-version=2.0'
        ContentType = 'application/json'
        Headers     = @{ Authorization = 'Bearer {0}' -f $accessToken.access_token }
        Body        = $consentGrantBody | ConvertTo-Json
    }
    Invoke-RestMethod @consentGrantSplat




    # # https://samcogan.com/provide-admin-consent-fora-azure-ad-applications-programmatically/


    # 3-8.aA6zV3.-I_.tGMTezQ0Em2oxVLu4Xn
    # bf0a1bb9-dac9-458f-8209-0273dce52e1a


    # # $clientId     = 'bf0a1bb9-dac9-458f-8209-0273dce52e1a'
    # $applicationId = '12f9ac58-cf1a-4201-b936-f4a5e4af5ecd'
    # $clientSecret  = '3-8.aA6zV3.-I_.tGMTezQ0Em2oxVLu4Xn'
    # $tenantId      = '5f36d76e-9089-4ef3-94fc-d1758088e39a'

    # $reqTokenBody = @{
    #     Grant_Type    = "client_credentials"
    #     Scope         = "https://graph.microsoft.com/.default"
    #     client_Id     = $applicationId # $clientId
    #     Client_Secret = $clientSecret
    # }
    # $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

    # $TokenResponse.access_token


    # $resourceId = ''(Get-AzureADApplication -ObjectId <application object ID>).RequiredResourceAccess

    # $body = @{
    #     clientId    = $applicationId # $clientId
    #     consentType = "AllPrincipals"
    #     principalId = $null
    #     resourceId  = $resourceId
    #     scope       = "Group.Read.All"
    #     startTime   = "2019-10-19T10:37:00Z"
    #     expiryTime  = "2019-10-19T10:37:00Z"
    # }
    # $apiUrl = "https://graph.microsoft.com/beta/oauth2PermissionGrants"
    # Invoke-RestMethod -Uri $apiUrl -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" }  -Method POST -Body $($body | convertto-json) -ContentType "application/json"








    # $requestBody = @{
    #     clientId    = $ClientId
    #     consentType = 'AllPrincipals'
    #     principalId = $null
    #     resourceId  = $ResourceId
    #     scope       = $Scope
    #     startTime   = '{0:yyyy-MM-ddTHH:mm:ssZ}' -f [System.DateTime]::UtcNow
    #     expiryTime  = '{0:yyyy-MM-ddTHH:mm:ssZ}' -f [System.DateTime]::UtcNow
    # }

    # $requestSplat = @{
    #     Uri     = 'https://graph.microsoft.com/beta/oauth2PermissionGrants'
    #     Method  = 'POST'
    #     Headers = @{
    #         ContentType   = 'application/json'
    #         Authorization = 'Bearer {0}' -f $AccessToken
    #     }
    #     Body    = ($requestBody | ConvertTo-Json)
    # }

    # Invoke-WebRequest @requestSplat
}
