<#
    .SYNOPSIS
        Store the tenant objects of the module context config file.
#>
function Import-MicrosoftOnlineTenant
{
    [CmdletBinding()]
    param
    (
        # Path to the context config file.
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        # The tenant name.
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        [SupportsWildcards()]
        [System.String[]]
        $Name
    )

    $objects = Get-Content -Path $Path -Encoding 'UTF8' | ConvertFrom-Json

    # Convert the imported objects into tenant objects. Decrypt the protected
    # secure string values.
    $tenants = @()
    foreach ($object in $objects)
    {
        try
        {
            # For the future, the property _Version can be used if the tenant
            # schema changes.
            $tenants += [PSCustomObject] @{
                PSTypeName            = 'MicrosoftOnlineFever.Tenant'
                Name                  = $object.Name
                TenantDomain          = $object.TenantDomain
                TenantId              = $object.TenantId
                ApplicationId         = $object.ApplicationId
                CertificateThumbprint = $object.CertificateThumbprint
                CertificateSecret     = $object.CertificateSecret | ConvertTo-SecureString
                CertificatePfx        = $object.CertificatePfx
            }
        }
        catch
        {
            Write-Warning "Failed to load a tenant: $_"
        }
    }

    # Filter the tenants if the Name parameter is specified.
    if ($PSBoundParameters.ContainsKey('Name') -and $Name.Count -gt 0)
    {
        $tenants = $tenants | Where-Object { $tenantName = $_; $Name | ForEach-Object { $tenantName -like $_ } }
    }

    $tenants = $tenants | Sort-Object -Property 'Name'

    Write-Output $tenants
}
