<#
    .SYNOPSIS
        Store the tenant objects in the module context config file.
#>
function Export-MicrosoftOnlineTenant
{
    [CmdletBinding()]
    param
    (
        # Path to the context config file.
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        # The tenant objects to store.
        [Parameter(Mandatory = $true)]
        [PSTypeName('MicrosoftOnlineFever.Tenant')]
        [System.Object[]]
        $Tenant
    )

    $objects = @()
    foreach ($currentTenant in $Tenant)
    {
        $objects += [PSCustomObject] @{
            _Version              = 1
            Name                  = $currentTenant.Name
            TenantDomain          = $currentTenant.TenantDomain
            TenantId              = $currentTenant.TenantId
            ApplicationId         = $currentTenant.ApplicationId
            ClientId              = $currentTenant.ClientId
            ClientSecret          = $currentTenant.ClientSecret | ConvertFrom-SecureString
            CertificateThumbprint = $currentTenant.CertificateThumbprint
            CertificateSecret     = $currentTenant.CertificateSecret | ConvertFrom-SecureString
            CertificatePfx        = $currentTenant.CertificatePfx
        }
    }

    ConvertTo-Json -InputObject $objects | Set-Content -Path $Path -Encoding 'UTF8' -Force
}
