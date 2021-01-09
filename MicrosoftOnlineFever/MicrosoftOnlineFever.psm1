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
