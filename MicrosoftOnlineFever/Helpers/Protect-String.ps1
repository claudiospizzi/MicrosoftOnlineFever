<#
    .SYNOPSIS
        Convert a string into a secure string.
#>
function Protect-String
{
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function', Target='Protect-String')]
    [OutputType([System.Security.SecureString])]
    param
    (
        # The string to protect.
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $String
    )

    $secureString = ConvertTo-SecureString -String $String -AsPlainText -Force
    return $secureString
}
