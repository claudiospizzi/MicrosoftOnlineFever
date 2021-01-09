<#
    .SYNOPSIS
        Register an application for PowerShell automation in Azure AD.

    .DESCRIPTION
        This command will register an application in the Azure AD used to
        perform PowerShell automation tasks. It will also create a local
        certificate and add it as authentication key to the application.

    .INPUTS
        None.

    .OUTPUTS
        System.String. Connection string to the application.

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
        # Credentails to connect to the Azure AD.
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
        [System.String]
        $ApplicationDirectoryRole = 'Company Administrator',

        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Alias('Preview')]
        [Switch]
        $UsePreviewModule
    )

    Test-MicrosoftOnlineModuleDependency -UsePreviewModule:$UsePreviewModule


    ## Azure AD Connection


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

    Write-Verbose "Azure AD Application => AppId: $($application.AppId)"
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

    try
    {
        $certificatePath     = [System.IO.Path]::GetTempFileName()
        $certificatePassword = ConvertTo-SecureString -String $application.AppId -Force -AsPlainText

        Export-PfxCertificate -Cert $certificate -FilePath $certificatePath -Password $certificatePassword -Force | Out-Null
        $certificatePfx = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certificatePath))
    }
    finally
    {
        Remove-Item -Path $certificatePath -ErrorAction 'SilentlyContinue'
    }

    Write-Verbose "Azure AD Application Cert => Thumbprint: $($certificate.Thumbprint)"
    Write-Verbose "Azure AD Application Cert => Subject: $($certificate.Subject)"


    ## Azure AD Application Key

    $keyIdentifier = $certificate.Thumbprint.Substring(0, 30)

    $key = Get-AzureADApplicationKeyCredential -ObjectId $application.ObjectId | Where-Object { [System.Text.Encoding]::Default.GetString($_.CustomKeyIdentifier) -eq $keyIdentifier }

    if ($null -ne $key)
    {
        Write-Verbose "Azure AD Application Key => Use existing Key"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Create App Key')) { return }

        Write-Verbose "Azure AD Application Key => Register the Key"

        $keySplat = @{
            ObjectId            = $application.ObjectId
            CustomKeyIdentifier = $keyIdentifier
            Type                = 'AsymmetricX509Cert'
            Usage               = 'Verify'
            Value               = [System.Convert]::ToBase64String($certificate.GetRawCertData())
            EndDate             = $certificate.NotAfter
        }
        $key = New-AzureADApplicationKeyCredential @keySplat
    }

    Write-Verbose "Azure AD Application Key => KeyId: $($key.KeyId)"


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


    ## Azure AD Application Role

    $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq $ApplicationDirectoryRole }

    $member = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object { $_.ObjectType -eq 'ServicePrincipal' -and $_.AppId -eq $application.AppId }

    if ($null -ne $member)
    {
        Write-Verbose "Azure AD Application Role => App is Member of $ApplicationDirectoryRole"
    }
    else
    {
        # Exit if the user does not confirm the application registration.
        if (-not $PSCmdlet.ShouldProcess($context.TenantDomain, 'Add App to Role')) { return }

        Write-Verbose "Azure AD Application Role => Add App to $ApplicationDirectoryRole"

        $member = Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $principal.ObjectId
    }


    $connectionString = '{0}:{1}:{2}:{3}' -f $context.TenantId, $application.AppId, $certificate.Thumbprint, $certificatePfx

    return $connectionString
}
