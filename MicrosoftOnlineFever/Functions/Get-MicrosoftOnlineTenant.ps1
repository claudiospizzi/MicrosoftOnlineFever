<#
    .SYNOPSIS
        Get all profiles for Microsoft Online in the Windows user profile.

    .DESCRIPTION
        .

    .INPUTS
        .

    .OUTPUTS
        MicrosoftOnlineAce

    .EXAMPLE
        PS C:\> Get-MicrosoftOnlineProfile
        Get all profiles.

    .EXAMPLE
        PS C:\> Get-MicrosoftOnlineProfile -Name 'Contoso', 'Adatum*'
        Get all profiles where the name is 'Contoso' or starts with 'Adatum'.

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
