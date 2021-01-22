<#
    .SYNOPSIS
        Test if the module dependencies are installed.

    .DESCRIPTION
        This function will test all required modules if the are installed. If a
        module is missing or not current, an exception is thrown. If the module
        is available, it will be imported into the global scope.

    .EXAMPLE
        PS C:\> Test-MicrosoftOnlineModuleDependency
        The the module dependencies.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Test-MicrosoftOnlineModuleDependency
{
    [CmdletBinding()]
    param
    (
        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Switch]
        $UsePreview
    )
}
