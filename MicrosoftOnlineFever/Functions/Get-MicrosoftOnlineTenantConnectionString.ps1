<#
    .SYNOPSIS
        Get the connection string for a registered Microsoft Online tenant.

    .DESCRIPTION
        Generate a connection string used to register a Microsoft Online tenant
        on another system or profile. The connection string contains secret
        information and must be protected.

    .INPUTS
        None.

    .OUTPUTS
        System.String. The tenant connection string.

    .EXAMPLE
        PS C:\> Get-MicrosoftOnlineTenantConnectionString -Name 'Contoso'
        The connection string for the Contoso tenant.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Get-MicrosoftOnlineTenantConnectionString
{
    [CmdletBinding()]
    param
    (
        # The tenant name.
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        [SupportsWildcards()]
        [System.String[]]
        $Name
    )

    $tenants = Get-MicrosoftOnlineTenant -Name $Name

    foreach ($tenant in $tenants)
    {
        $clientSecret      = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Unprotect-SecureString -SecureString $tenant.ClientSecret)))
        $certificateSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Unprotect-SecureString -SecureString $tenant.CertificateSecret)))

        $connectionString = '{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}' -f $tenant.TenantId,
                                                                 $tenant.TenantDomain,
                                                                 $tenant.ApplicationId,
                                                                 $tenant.ClientId,
                                                                 $clientSecret,
                                                                 $tenant.CertificateThumbprint,
                                                                 $certificateSecret,
                                                                 $tenant.CertificatePfx

        Write-Output $connectionString
    }
}

# Register the argument completer for the Name parameter
Register-ArgumentCompleter -CommandName 'Get-MicrosoftOnlineTenantConnectionString' -ParameterName 'Name' -ScriptBlock {
    param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    Import-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Name)
    }
}
