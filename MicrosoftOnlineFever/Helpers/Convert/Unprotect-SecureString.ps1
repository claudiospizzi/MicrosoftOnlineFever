<#
    .SYNOPSIS
        Convert a secure string into a string.
#>
function Unprotect-SecureString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        # The secure string to reveal.
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Security.SecureString]
        $SecureString
    )

    $currentCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList 'Dummy', $SecureString
    return $currentCredential.GetNetworkCredential().Password
}
