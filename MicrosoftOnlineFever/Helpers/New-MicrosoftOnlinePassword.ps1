<#
    .SYNOPSIS
        Generate a password for a Microsoft Online user.
#>
function New-MicrosoftOnlinePassword
{
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Scope='Function', Target='New-MicrosoftOnlinePassword')]
    [OutputType([System.String])]
    param
    (
        # Length of the password
        [Parameter(Mandatory = $false)]
        [ValidateRange(16, 256)]
        [System.String]
        $Length = 32
    )

    $password = ''

    for ($i = 0; $i -lt $Length; $i++)
    {
        $type = Get-Random -Minimum 0 -Maximum 3
        switch ($type)
        {
            0 { $password += [char](Get-Random -Minimum 48 -Maximum 58) }
            1 { $password += [char](Get-Random -Minimum 65 -Maximum 91) }
            2 { $password += [char](Get-Random -Minimum 97 -Maximum 123) }
        }

        Start-Sleep -Milliseconds 1
    }

    Write-Output $password
}
