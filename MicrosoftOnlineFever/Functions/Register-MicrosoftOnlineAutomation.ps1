<#
    .SYNOPSIS
        Register an application with key credentials and permissions for
        PowerShell automation in Azure AD.

    .DESCRIPTION
        This command will register an application in the Azure AD used set
        perform PowerShell automation tasks. It will also create a local
        certificate and add it as authentication key to the application.
        Finally the permissions in the tenant is applied to the service
        principal

    .INPUTS
        None.

    .OUTPUTS
        MicrosoftOnlineFever.Tenant. Tenant for the created application.

    .EXAMPLE
        PS C:\> Register-MicrosoftOnlineAutomation
        Create a new application in the Azure AD for the automation with
        default properties.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Register-MicrosoftOnlineAutomation
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        # Tenant name used to store this regsitered app in the module context.
        [Parameter(Mandatory = $false)]
        [System.String]
        $Name,

        # Credential to connect to the Azure AD. Only usable if two factor is
        # not enabled. If the credential is not specified, a UI popup will
        # prompt for the Microsoft Online login.
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $Credential,

        # Name of the Azure AD application.
        [Parameter(Mandatory = $false)]
        [System.String]
        $ApplicationName = 'PowerShell Automation',

        # Identifier Uri for the Azure AD application. The placeholder
        # <TenantDomain> is replaced with the actual tenant domain
        [Parameter(Mandatory = $false)]
        [System.String]
        $ApplicationIdentifierUri = 'https://<TenantDomain>/powershell-automation',

        # Directory role used by the Azure AD application.
        [Parameter(Mandatory = $false)]
        [System.String[]]
        $ApplicationDirectoryRole = @('Company Administrator', 'Global Administrator', 'Exchange Administrator', 'SharePoint Administrator'),

        # API permissions for the Azure AD application.
        [Parameter(Mandatory = $false)]
        [System.String[]]
        $ApplicationApiPermission = @('Office 365 Exchange Online:Exchange.ManageAsApp', 'Office 365 SharePoint Online:Sites.FullControl.All'),

        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Alias('Preview')]
        [Switch]
        $UsePreviewModule
    )

    Test-MicrosoftOnlineModuleDependency -Scope 'AzureAD' -UsePreviewModule:$UsePreviewModule


    ## Azure AD Connection

    $context = [PSCustomObject] @{ TenantId = '5f36d76e-9089-4ef3-94fc-d1758088e39a'; TenantDomain = 'arcadespizzilab.onmicrosoft.com' }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        Write-Verbose 'Azure AD Connection => Open by using the specified credential'

        $context = Connect-AzureAD -Credential $Credential
    }
    else
    {
        Write-Verbose 'Azure AD Connection => Open by using the UI to login...'

        $context = Connect-AzureAD
    }

    # Exit if the connection was not succesful, e.g. is empty.
    if ($null -eq $context)
    {
        throw 'User authentication not successful'
    }

    # Patch the application identifier uri with the tenant domain.
    $ApplicationIdentifierUri = $ApplicationIdentifierUri.Replace('<TenantDomain>', $context.TenantDomain)

    Write-Verbose "Azure AD Connection => TenantId: $($context.TenantId)"
    Write-Verbose "Azure AD Connection => TenantDomain: $($context.TenantDomain)"


    ## Azure AD Application

    $application = Get-AzureADApplication | Where-Object { $_.IdentifierUris -contains $ApplicationIdentifierUri }

    if ($null -ne $application)
    {
        if ($application.DisplayName -ne $ApplicationName)
        {
            throw "Mismatch between existing application '$($application.DisplayName)' and the desired application '$ApplicationName'"
        }

        Write-Verbose "Azure AD Application => Use existing Application"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Register Application')) { return }

        Write-Verbose "Azure AD Application => Register the Application"

        $applicationSplat = @{
            DisplayName    = $ApplicationName
            IdentifierUris = $ApplicationIdentifierUri
        }
        $application = New-AzureADApplication @applicationSplat
    }

    $applicationReplyUrl = 'https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/{0}/isMSAApp/' -f $application.AppId
    if ($application.ReplyUrls -notcontains $applicationReplyUrl)
    {
        Write-Verbose "Azure AD Application => Register the Reply Url"

        Set-AzureADApplication -ObjectId $application.ObjectId -ReplyUrls $applicationReplyUrl
        $application = Get-AzureADApplication | Where-Object { $_.IdentifierUris -contains $ApplicationIdentifierUri }
    }

    Write-Verbose "Azure AD Application => AppId: $($application.AppId)"
    Write-Verbose "Azure AD Application => ObjectId: $($application.ObjectId)"
    Write-Verbose "Azure AD Application => DisplayName: $($application.DisplayName)"


    ## Azure AD Application Cert

    $certificateStore   = 'Cert:\CurrentUser\My'
    $certificateSubject = 'CN={0}, OU={1}, O={2}' -f $context.TenantDomain, $application.AppId, $context.TenantId

    $certificate = Get-ChildItem -Path $certificateStore | Where-Object { $_.Subject -eq $certificateSubject -and $_.HasPrivateKey } | Select-Object -First 1

    if ($null -ne $certificate)
    {
        Write-Verbose "Azure AD Application Cert => Use existing Certificate"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Create Certificate')) { return }

        Write-Verbose "Azure AD Application Cert => Generate the Certificate"

        $certificateSplat = @{
            Subject           = $certificateSubject
            NotAfter          = [System.DateTime]::Now.AddYears(10)
            CertStoreLocation = $certificateStore
            KeyExportPolicy   = 'Exportable'
            Provider          = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            Type              = 'CodeSigningCert'
            KeySpec           = 'Signature'
        }
        $certificate = New-SelfSignedCertificate @certificateSplat
    }

    Write-Verbose "Azure AD Application Cert => Thumbprint: $($certificate.Thumbprint)"
    Write-Verbose "Azure AD Application Cert => Subject: $($certificate.Subject)"


    ## Azure AD Application Cert Key

    $certKeyIdentifier = $certificate.Thumbprint.Substring(0, 30)

    $certKey = Get-AzureADApplicationKeyCredential -ObjectId $application.ObjectId | Where-Object { [System.Text.Encoding]::Default.GetString($_.CustomKeyIdentifier) -eq $certKeyIdentifier }

    if ($null -ne $certKey)
    {
        Write-Verbose "Azure AD Application Cert Key => Use existing Key"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Create App Cert Key')) { return }

        Write-Verbose "Azure AD Application Cert Key => Register the Key"

        $certKeySplat = @{
            ObjectId            = $application.ObjectId
            CustomKeyIdentifier = $certKeyIdentifier
            Type                = 'AsymmetricX509Cert'
            Usage               = 'Verify'
            Value               = [System.Convert]::ToBase64String($certificate.GetRawCertData())
            EndDate             = $certificate.NotAfter
        }
        $certKey = New-AzureADApplicationKeyCredential @certKeySplat
    }

    Write-Verbose "Azure AD Application Cert Key => KeyId: $($certKey.KeyId)"


    ## Azure AD Application Secret Key

    $secretKeyIdentifier = [System.Guid]::NewGuid().Guid.Replace('-', '').Substring(0, 30)

    Write-Verbose "Azure AD Application Secret Key => Register the key"

    # Exit if the user does not confirm the application registration.
    if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Create App Secret Key')) { return }

    $secretKey = New-AzureADApplicationPasswordCredential -ObjectId $application.ObjectId -CustomKeyIdentifier $secretKeyIdentifier -EndDate ([System.DateTime]::UtcNow.AddYears(10))


    ## Azure AD Application Principal

    $principal = Get-AzureADServicePrincipal -All $true | Where-Object { $_.AppId -eq $application.AppId }

    if ($null -ne $principal)
    {
        Write-Verbose "Azure AD Application Principal => Use existing Principal"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Create App Principal')) { return }

        Write-Verbose "Azure AD Application Principal => Create the Principal"

        $principal = New-AzureADServicePrincipal -AppId $application.AppId
    }

    Write-Verbose "Azure AD Application Principal => ObjectId: $($principal.ObjectId)"


    ## Azure AD Application Role Template

    for ($i = 0; $i -lt $ApplicationDirectoryRole.Count; $i++)
    {
        $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq $ApplicationDirectoryRole[$i] }

        if ($null -eq $role)
        {
            $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $ApplicationDirectoryRole[$i] }

            if ($null -ne $roleTemplate)
            {
                # Exit if the user does not confirm the application registration.
                if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Enable Role Template')) { return }

                Write-Verbose "Azure AD Application Role Template [$i] => Enable Role Template"

                Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
            }
            else
            {
                Write-Verbose "Azure AD Application Role Template [$i] => Role Template missing"
            }
        }
        else
        {
            Write-Verbose "Azure AD Application Role Template [$i] => Use existing Role Template"
        }

        Write-Verbose "Azure AD Application Role Template [$i] => DisplayName: $($ApplicationDirectoryRole[$i])"
    }


    ## Azure AD Application Role

    for ($i = 0; $i -lt $ApplicationDirectoryRole.Count; $i++)
    {
        $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq $ApplicationDirectoryRole[$i] }

        if ($null -ne $role)
        {
            $member = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object { $_.ObjectType -eq 'ServicePrincipal' -and $_.AppId -eq $application.AppId }

            if ($null -ne $member)
            {
                Write-Verbose "Azure AD Application Role [$i] => Use existing Role"
            }
            else
            {
                # Exit if the user does not confirm the application registration.
                if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Add App to Role')) { return }

                Write-Verbose "Azure AD Application Role [$i] => Add App to Role"

                $member = Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $principal.ObjectId
            }

            Write-Verbose "Azure AD Application Role [$i] => DisplayName: $($ApplicationDirectoryRole[$i])"
        }
    }


    ## Azure AD API Permissions

    for ($i = 0; $i -lt $ApplicationApiPermission.Count; $i++)
    {
        $apiServicePrincipalName = $ApplicationApiPermission[$i].Split(':')[0]
        $apiPermissionName       = $ApplicationApiPermission[$i].Split(':')[1]

        Write-Verbose "Azure AD Application API Permission [$i] => ServicePrincipal: $apiServicePrincipalName"
        Write-Verbose "Azure AD Application API Permission [$i] => Permission: $apiServicePrincipalName"

        $apiServicePrincipal = Get-AzureADServicePrincipal -All $true | Where-Object { $_.DisplayName -eq $apiServicePrincipalName }
        $apiPermission = $apiServicePrincipal.AppRoles | Where-Object { $_.Value -eq $apiPermissionName }

        $apiResourceAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]::new()
        $apiResourceAccess.ResourceAppId = $apiServicePrincipal.AppId
        $apiResourceAccess.ResourceAccess = [Microsoft.Open.AzureAD.Model.ResourceAccess]::new($apiPermission.Id, 'Role')

        $apiResourceAccessAll = @(Get-AzureADApplication -ObjectId $application.ObjectId | Select-Object -ExpandProperty 'RequiredResourceAccess')
        $apiResourceAccessExist = $false
        if ($null -ne $apiResourceAccessAll -and $apiResourceAccessAll.Count -gt 0)
        {
            $apiResourceAccessExist = [System.Boolean] ($apiResourceAccessAll | Where-Object { $_.ResourceAppId -eq $apiResourceAccess.ResourceAppId -and $_.ResourceAccess.Id -eq $apiResourceAccess.ResourceAccess.Id -and $_.ResourceAccess.Type -eq $apiResourceAccess.ResourceAccess.Type })
        }

        if ($apiResourceAccessExist)
        {
            Write-Verbose "Azure AD Application API Permission [$i] => Use existing Resource Access"
        }
        else
        {
            # Exit if the user does not confirm the application registration.
            if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Add Resource Access')) { return }

            Write-Verbose "Azure AD Application API Permission [$i] => Register new Resource Access"

            # Use an ArrayList instead of an array, becaue the type used object
            # type [Microsoft.Open.AzureAD.Model.RequiredResourceAccess] has a
            # behaviour that adding elements to array (+=) always ends in an
            # error: Does not contain a method named 'op_Addition'.
            $apiResourceAccessNew = [System.Collections.ArrayList]::new()
            $apiResourceAccessAll | ForEach-Object { $apiResourceAccessNew.Add($_) | Out-Null }
            $apiResourceAccessNew.Add($apiResourceAccess) | Out-Null

            Set-AzureADApplication -ObjectId $application.ObjectId -RequiredResourceAccess $apiResourceAccessNew
        }

        # Grant-MicrosoftOnlineAdminConsent -TenantId $context.TenantId -ClientId $application.AppId -ClientId2 $application.ObjectId -ClientSecret (Protect-String -String $secretKey.Value) -ResourceId $principal.ObjectId -Scope $apiPermissionName
    }

    # Start the browser to request the admin consent by using the Internet
    # Explorer in the InPrivate mode.
    $adminConsentUrl = "https://login.microsoftonline.com/$($context.TenantId)/adminconsent?client_id=$($application.AppId)"
    Write-Verbose "Grant admin constent: $adminConsentUrl"
    & 'C:\Program Files\Internet Explorer\iexplore.exe' -private $adminConsentUrl


    ## MicrosoftOnlineFever Tenant

    if (-not $PSBoundParameters.ContainsKey('Name'))
    {
        $Name = $context.TenantDomain.Split('.')[0].ToUpper()
    }

    # Create and return the tenant.
    $tenantSplat = @{
        Name                  = $Name
        TenantId              = $context.TenantId
        TenantDomain          = $context.TenantDomain
        ApplicationId         = $application.AppId
        ClientId              = $application.AppId
        ClientSecret          = Protect-String -String $secretKey.Value
        CertificateThumbprint = $certificate.Thumbprint
    }
    Add-MicrosoftOnlineTenant @tenantSplat
}
