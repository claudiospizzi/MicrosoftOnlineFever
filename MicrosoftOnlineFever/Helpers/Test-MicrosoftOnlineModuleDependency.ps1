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
        # The connection scope.
        [Parameter(Mandatory = $false)]
        [ValidateSet('AzureAD', 'MSOL', 'Graph', 'Azure', 'Exchange', 'SecurityCompliance', 'SharePoint', 'Teams')]
        [System.String[]]
        $Scope,

        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Switch]
        $UsePreviewModule
    )

    $modules = Get-Content -Path "$Script:PSModulePath\Configs\Dependencies.json" | ConvertFrom-Json
    if ($UsePreviewModule.IsPresent)
    {
        $modules = $modules.PreviewModules
    }
    else
    {
        $modules = $modules.Modules
    }

    foreach ($module in $modules)
    {
        # Only process the dependency module if the scope does match.
        if (($module.Scope | Where-Object { $Scope -contains $_ }))
        {
            $moduleName            = $module.Name
            $moduleRequiredVersion = $module.Version

            Write-Verbose "Module Dependency => Verify $moduleName"

            $moduleInstalledVersion = Get-Module -Name $moduleName -ListAvailable -Verbose:$false |
                                        Sort-Object -Property 'Version' |
                                            Select-Object -ExpandProperty 'Version' -Last 1

            if ($null -eq $moduleInstalledVersion)
            {
                throw "Module $moduleName not installed, please install the module."
            }

            if ($moduleInstalledVersion -lt $moduleRequiredVersion)
            {
                throw "Module $moduleName is not current, please update to at $moduleRequiredVersion or later."
            }

            Write-Verbose "Module Dependency => Import $moduleName $moduleInstalledVersion"

            Import-Module -Name $moduleName -RequiredVersion $moduleInstalledVersion -Global -Verbose:$false
        }
    }
}
