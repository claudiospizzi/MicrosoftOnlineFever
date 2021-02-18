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
        [Parameter(Mandatory = $false)]
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
            $tenants += [PSCustomObject] @{
                PSTypeName            = 'MicrosoftOnlineFever.Tenant'
                Name                  = $object.Name
                TenantId              = $object.TenantId
                TenantDomain          = $object.TenantDomain
                FallbackUsername      = $object.FallbackUsername
                FallbackPassword      = $object.FallbackPassword | ConvertTo-SecureString
                ApplicationId         = $object.ApplicationId
                ClientId              = $object.ClientId
                ClientSecret          = $object.ClientSecret | ConvertTo-SecureString
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
    if ($PSBoundParameters.ContainsKey('Name') -and $Name -and $Name.Count -gt 0)
    {
        $tenants = $tenants | Where-Object { $tenantName = $_.Name; $Name | Where-Object { $tenantName -like $_ } }
    }

    $tenants = $tenants | Sort-Object -Property 'Name'

    if ($null -ne $tenants)
    {
        Write-Output $tenants
    }
}
