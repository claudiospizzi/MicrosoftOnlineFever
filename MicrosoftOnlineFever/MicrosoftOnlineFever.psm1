<#
    .SYNOPSIS
        Root module file.

    .DESCRIPTION
        The root module file loads all classes, helpers and functions into the
        module context.
#>

# Get and dot source all classes (internal)
Split-Path -Path $PSCommandPath |
    Get-ChildItem -Filter 'Classes' -Directory |
        Get-ChildItem -Include '*.ps1' -File -Recurse |
            ForEach-Object { . $_.FullName }

# Get and dot source all helper functions (internal)
Split-Path -Path $PSCommandPath |
    Get-ChildItem -Filter 'Helpers' -Directory |
        Get-ChildItem -Include '*.ps1' -File -Recurse |
            ForEach-Object { . $_.FullName }

# Get and dot source all external functions (public)
Split-Path -Path $PSCommandPath |
    Get-ChildItem -Filter 'Functions' -Directory |
        Get-ChildItem -Include '*.ps1' -File -Recurse |
            ForEach-Object { . $_.FullName }

# Define the module meta information
$Script:PSModulePath    = Split-Path -Path $PSCommandPath
$Script:PSModuleName    = Split-Path -Path $PSCommandPath -Leaf | ForEach-Object { $_.Split('.')[0] }
$Script:PSModuleVersion = (Import-PowerShellDataFile -Path "$Script:PSModulePath\$Script:PSModuleName.psd1")['ModuleVersion']

# Define module behaviour
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Module configuration files in the user app data directory
$Script:MicrosoftOnlineFeverConfigPath = '{0}\PowerShell\MicrosoftOnlineFever' -f $Env:AppData
$Script:MicrosoftOnlineFeverTenantPath = '{0}\tenants.json' -f $Script:MicrosoftOnlineFeverConfigPath
if (-not (Test-Path -Path $Script:MicrosoftOnlineFeverConfigPath))
{
    New-Item -Path $Script:MicrosoftOnlineFeverConfigPath -ItemType 'Directory' | Out-Null
}
if (-not (Test-Path -Path $Script:MicrosoftOnlineFeverTenantPath))
{
    ConvertTo-Json -InputObject @() | Set-Content -Path $Script:MicrosoftOnlineFeverTenantPath -Encoding 'UTF8' -Force
}
