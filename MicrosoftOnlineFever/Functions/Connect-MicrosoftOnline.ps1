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
        PS C:\> Connect-MicrosoftOnline
        .

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Connect-MicrosoftOnline
{
    [CmdletBinding()]
    [Alias('aad', 'o365', 'm365')]
    param
    (
        # The tenant name.
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet('AzureAD', 'MSOL', 'Graph', 'Azure', 'Exchange', 'SecurityCompliance', 'SharePoint', 'Teams')]
        [System.String[]]
        $Scope,

        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Alias('Preview')]
        [Switch]
        $UsePreviewModule
    )

    Test-MicrosoftOnlineModuleDependency -UsePreviewModule:$UsePreviewModule

    # Define the default scopes, if non was specified.
    if (-not $PSBoundParameters.ContainsKey('Scope'))
    {
        $Scope = 'AzureAD', 'Graph', 'Azure', 'Exchange', 'SharePoint', 'Teams'
    }

    # Ensure that the Exchange scope is used if the SecurityCompliance is
    # requested. This depends on the Exchange scope.
    if ($Scope -contains 'SecurityCompliance' -and $Scope -notcontains 'Exchange')
    {
        $Scope += 'Exchange'
    }

    $tenant = Get-MicrosoftOnlineTenant -Name $Name
    if ($null -eq $tenant)
    {
        throw "Tenant named $Name not found."
    }

    $orderedScopes = 'AzureAD', 'MSOL', 'Graph', 'Azure', 'Exchange', 'SecurityCompliance', 'SharePoint', 'Teams'

    foreach ($currentScope in $orderedScopes)
    {
        if ($currentScope -in $Scope)
        {
            try
            {
                $connection = [PSCustomObject] @{
                    PSTypeName = 'MicrosoftOnlineFever.Connection'
                    Scope      = $currentScope
                    Module     = ''
                    Tenant     = ''
                    Domain     = ''
                }

                # Microsoft Azure Active Directory PowerShell for Graph (*-AzureAD*)
                if ($currentScope -eq 'AzureAD')
                {
                    $contextAzureAD = Connect-AzureAD -TenantId $tenant.TenantId -ApplicationId $tenant.ApplicationId -CertificateThumbprint $tenant.CertificateThumbprint

                    $contextAzureAD | ForEach-Object {
                        $connection.Module = $(if ($UsePreviewModule.IsPresent) { 'AzureADPreview' } else { 'AzureAD' })
                        $connection.Tenant = $_.TenantId
                        $connection.Domain = $_.TenantDomain
                    }
                }

                # Microsoft Azure Active Directory Module for Windows PowerShell (*-Msol*)
                if ($currentScope -eq 'MSOL')
                {
                    # Connect-MsolService

                    throw 'The MSOL module is currently not supported.'
                }

                # Microsoft Graph (*-Mg*)
                if ($currentScope -eq 'Graph')
                {
                    Connect-MgGraph -TenantId $tenant.TenantId -ClientID $tenant.ApplicationId -CertificateThumbprint $tenant.CertificateThumbprint | Out-Null

                    Get-MgContext | ForEach-Object {
                        $connection.Module = 'Microsoft.Graph'
                        $connection.Tenant = $_.TenantId
                        $connection.Domain = 'n/a'
                    }
                }

                # Azure PowerShell (*-Az*)
                if ($currentScope -eq 'Azure')
                {
                    $contextAzure = Connect-AzAccount -Tenant $tenant.TenantId -ApplicationId $tenant.ApplicationId -CertificateThumbprint $tenant.CertificateThumbprint

                    $contextAzure | ForEach-Object {
                        $connection.Module = 'Az'
                        $connection.Tenant = $_.Context.Tenant.Id
                        $connection.Domain = 'n/a'
                    }
                }

                # Exchange Online PowerShell V2 (*-EXO* / Classical Exchange Cmdlets)
                if ($currentScope -eq 'Exchange')
                {
                    Connect-ExchangeOnline -Organization $tenant.TenantDomain -AppId $tenant.ApplicationId -CertificateThumbprint $tenant.CertificateThumbprint -ShowBanner:$false | Out-Null

                    Get-OrganizationConfig | ForEach-Object {
                        $connection.Module = 'ExchangeOnlineManagement'
                        $connection.Tenant = 'n/a'
                        $connection.Domain = $_.Name
                    }
                }

                # Security & Compliance (based on Exchange Online PowerShell V2)
                if ($currentScope -eq 'SecurityCompliance')
                {
                    # Connect-IPPSSession

                    throw 'The MSOL module is currently not supported.'
                }

                # Microsoft 365 Patterns and Practices PowerShell Cmdlets (*-PnP*)
                if ($currentScope -eq 'SharePoint')
                {
                    # Disable update change and telemetry
                    $Env:PNPPOWERSHELL_UPDATECHECK = $false
                    $Env:PNPPOWERSHELL_DISABLETELEMETRY = $true

                    Connect-PnPOnline -ClientId $tenant.ApplicationId -CertificateBase64Encoded $tenant.CertificatePfx -CertificatePassword $tenant.CertificateSecret -Url "https://$($tenant.TenantName).sharepoint.com" -Tenant $tenant.TenantDomain -Verbose:$false | Out-Null

                    Get-PnPConnection| ForEach-Object {
                        $connection.Module = 'PnP.PowerShell'
                        $connection.Tenant = 'n/a'
                        $connection.Domain = $_.Tenant
                    }
                }

                # Microsoft Teams PowerShell
                if ($currentScope -eq 'Teams')
                {
                    $contextTeams = Connect-MicrosoftTeams -TenantId $tenant.TenantId -ApplicationId $tenant.ApplicationId -CertificateThumbprint $tenant.CertificateThumbprint

                    $contextTeams | ForEach-Object {
                        $connection.Module = 'MicrosoftTeams'
                        $connection.Tenant = $_.TenantId.Guid
                        $connection.Domain = $_.TenantDomain
                    }
                }

                Write-Output $connection
            }
            catch
            {
                Write-Warning "Failed to connect to $currentScope with: $_"
            }
        }
    }




    # $tenant

    # $tenantId, $applicationId, $certificateThumbprint, $certificatePfx = $ConnectionString.Split(':')

    # if (-not (Test-Path "Cert:\CurrentUser\My\$certificateThumbprint"))
    # {
    #     # ToDo: Import Pfx...
    # }

    #


    # $azureAccessToken = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.AccessToken.AccessToken
    # Connect-MsolService -AccessToken $azureAccessToken


    # https://docs.microsoft.com/en-us/powershell/azure/active-directory/signing-in-service-principal?view=azureadps-2.0
    # https://erjenrijnders.nl/2018/08/30/azuread-login-without-credentials-unattended/
}

# Register the argument completer for the Name parameter
Register-ArgumentCompleter -CommandName 'Connect-MicrosoftOnline' -ParameterName 'Name' -ScriptBlock {
    param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    Import-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Name)
    }
}


# $clientId = [System.Guid]::NewGuid().Guid
# $tenantId = 'arcadespizzilab.onmicrosoft.com'
# $resourceId = 'https://graph.windows.net'
# $redirectUri = new-object System.Uri("urn:ietf:wg:oauth:2.0:oob")
# $login = 'https://login.microsoftonline.com'

# $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("{0}/{1}" -f $login,$tenantId);
# $authenticationResult = $authContext.AcquireToken($resourceId,$clientID,$redirectUri);
# $token = $authenticationResult.AccessToken
