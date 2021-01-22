<#
    .SYNOPSIS
        Add a Microsoft Online tenant to the module context.

    .DESCRIPTION
        The MicrosoftOnlineFever module stores the tenants in the module
        context. The context is loacted as config file in the current user
        AppData folder: $Env:AppData\PowerShell\MicrosoftOnlineFever\.

    .INPUTS
        None.

    .OUTPUTS
        MicrosoftOnlineFever.Tenant. The tenant object.

    .EXAMPLE
        PS C:\> Add-MicrosoftOnlineTenant -Name 'Contoso' -ConnectionString $connectionString
        Add the Contoso tenant to the module context.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Add-MicrosoftOnlineTenant
{
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (
        # Context tenant name.
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        # Name of the tenant domain.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidatePattern('^[a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [System.String]
        $TenantDomain,

        # Id of the tenant.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')]
        [System.String]
        $TenantId,

        # Id of the PowerShell Automation application in the tenant.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')]
        [System.String]
        $ApplicationId,

        # Id of the PowerShell Automation client secret.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidatePattern('^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')]
        [System.String]
        $ClientId,

        # PowerShell Automation client secret.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.Security.SecureString]
        $ClientSecret,

        # Thumbprint of the application certficate for the authentication.
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [System.String]
        $CertificateThumbprint,

        # The secret for the certificate PFX.
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Security.SecureString]
        $CertificateSecret,

        # Base64 encoded certificate PFX including the private key. If the
        # certificate is missing, it must already exist in the personal store.
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidatePattern('^[0-9a-zA-Z+=\/]*$')]
        [System.String]
        $CertificatePfx,

        # As an alternative, the connection string can be passed to create the
        # tenant. If the certificate secret and PFX part are empty, the
        # certificate must already exist in the personal store.
        [Parameter(Mandatory = $true, ParameterSetName = 'ConnectionString')]
        [System.String]
        $ConnectionString
    )

    if ($PSCmdlet.ParameterSetName -eq 'ConnectionString')
    {
        $TenantDomain, $TenantId, $ApplicationId, $ClientId, $clientSecretPlain, $CertificateThumbprint, $certificateSecretPlain, $CertificatePfx = $ConnectionString.Split(':')

        $ClientSecret      = Protect-String -String ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($clientSecretPlain)))
        $CertificateSecret = Protect-String -String $certificateSecretPlain
    }

    $TenantId              = $TenantId.ToLower()
    $ApplicationId         = $ApplicationId.ToLower()
    $CertificateThumbprint = $CertificateThumbprint.ToUpper()

    # If the certifcate was not specified, try to get the certificate details
    # from the store. If the certificate was specified, add the certificate to
    # the store if it does not exist there.
    if ([System.String]::IsNullOrEmpty($CertificateSecret) -or [System.String]::IsNullOrEmpty($CertificatePfx))
    {
        try
        {
            $certificatePath   = [System.IO.Path]::GetTempFileName()
            $CertificateSecret = ConvertTo-SecureString -String $application.AppId -Force -AsPlainText

            Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$CertificateThumbprint" -FilePath $certificatePath -Password $CertificateSecret -Force | Out-Null
            $CertificatePfx = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($certificatePath))
        }
        catch
        {
            throw "Certificate not specified by paramter and exporting of the user store failed: $_"
        }
        finally
        {
            Remove-Item -Path $certificatePath -ErrorAction 'SilentlyContinue'
        }
    }
    elseif (-not (Get-ChildItem -Path 'Cert:\CurrentUser\My'| Where-Object { $_.Thumbprint -eq $CertificateThumbprint -and $_.HasPrivateKey }))
    {
        try
        {
            $certificatePath = [System.IO.Path]::GetTempFileName()

            [System.IO.File]::WriteAllBytes($certificatePath, [System.Convert]::FromBase64String($CertificatePfx))
            Import-PfxCertificate -FilePath $certificatePath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $CertificateSecret -Exportable
        }
        catch
        {
            throw "Certificate specified by paramter can not be imported: $_"
        }
        finally
        {
            Remove-Item -Path $certificatePath -ErrorAction 'SilentlyContinue'
        }
    }

    # Create a new tenant object, ready to export to the context.
    $tenant = [PSCustomObject] @{
        PSTypeName            = 'MicrosoftOnlineFever.Tenant'
        Name                  = $Name
        TenantDomain          = $TenantDomain
        TenantId              = $TenantId
        ApplicationId         = $ApplicationId
        ClientId              = $ClientId
        ClientSecret          = $ClientSecret
        CertificateThumbprint = $CertificateThumbprint
        CertificateSecret     = $CertificateSecret
        CertificatePfx        = $CertificatePfx
    }

    # Load all tenants, add the new tenant to the list. Replace if a tenant
    # with the desired name does already exist. At the end, store the new
    # list.
    [System.Object[]] $tenants = Import-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath | Where-Object { $_.Name -ne $tenant.Name }
    $tenants += $tenant
    Export-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath -Tenant $tenants

    Write-Output $tenant
}
