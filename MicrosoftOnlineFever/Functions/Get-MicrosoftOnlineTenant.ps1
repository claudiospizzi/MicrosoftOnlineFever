<#
    .SYNOPSIS
        Get Microsoft Online tenants of the module context.

    .DESCRIPTION
        The MicrosoftOnlineFever module stores the tenants in the module
        context. The context is loacted as config file in the current user
        AppData folder: $Env:AppData\PowerShell\MicrosoftOnlineFever\.

    .INPUTS
        None.

    .OUTPUTS
        MicrosoftOnlineFever.Tenant. The tenant object.

    .EXAMPLE
        PS C:\> Get-MicrosoftOnlineTenant
        Get all tenants.

    .EXAMPLE
        PS C:\> Get-MicrosoftOnlineTenant -Name 'Contoso', 'Adatum*'
        Get all tenants where the name is 'Contoso' or starts with 'Adatum'.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Get-MicrosoftOnlineTenant
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

    Import-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath -Name $Name
}

# Register the argument completer for the Name parameter
Register-ArgumentCompleter -CommandName 'Get-MicrosoftOnlineTenant' -ParameterName 'Name' -ScriptBlock {
    param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    Import-MicrosoftOnlineTenant -Path $Script:MicrosoftOnlineFeverTenantPath | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Name)
    }
}
