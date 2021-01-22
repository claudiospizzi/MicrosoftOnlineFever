<#
    .SYNOPSIS
        Convert the connection config to a connection string.

    .DESCRIPTION
        This function will convert the connection config object to a connection
        string.

    .EXAMPLE
        PS C:\> ConvertTo-MicrosoftOnlineConnectionString -ConnectionConfig $connectionConfig
        Convert the connection config to the connection string.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function ConvertTo-MicrosoftOnlineConnectionString
{
    [CmdletBinding()]
    param
    (
        # The connection config object.
        [Parameter(Mandatory = $true)]
        [PSTypeName('MicrosoftOnlineFever.ConnectionConfig')]
        $ConnectionConfig
    )



    # $connectionString = '{0}:{1}' -f $ConnectionConfig.TenantDomain





}
