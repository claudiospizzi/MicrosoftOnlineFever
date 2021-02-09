[![PowerShell Gallery - MicrosoftOnlineFever](https://img.shields.io/badge/PowerShell_Gallery-MicrosoftOnlineFever-0072C6.svg)](https://www.powershellgallery.com/packages/MicrosoftOnlineFever)
[![GitHub - Release](https://img.shields.io/github/release/claudiospizzi/MicrosoftOnlineFever.svg)](https://github.com/claudiospizzi/MicrosoftOnlineFever/releases)
[![AppVeyor - main](https://img.shields.io/appveyor/ci/claudiospizzi/MicrosoftOnlineFever/main.svg)](https://ci.appveyor.com/project/claudiospizzi/MicrosoftOnlineFever/branch/main)

# MicrosoftOnlineFever PowerShell Module

PowerShell module with functions to connect and manage Microsoft Online.

## Introduction

This module is a helper module to register the Azure AD application on a tenant,
which then is used to silently connect to the various modules around Microsoft
cloud services. The option to create a connection string for a tenant
applications makes it possible, to pass the connection information to other
users and machines.

The following PowerShell modules currently support the silent certificate based
authentication to the Microsoft cloud:

- AzureAD ([Azure](https://www.powershellgallery.com/packages?q=AzureAD) module)
- Graph ([Microsoft.Graph](https://www.powershellgallery.com/packages?q=Microsoft.Graph) modules)
- Azure ([Az](https://www.powershellgallery.com/packages?q=Az) modules)
- Exchange Online ([ExchangeOnlineManagement](https://www.powershellgallery.com/packages?q=ExchangeOnlineManagement) module)
- SharePoint Online ([PnP.PowerShell](https://www.powershellgallery.com/packages?q=PnP.PowerShell) module)
- Microsoft Teams ([MicrosoftTeams](https://www.powershellgallery.com/packages?q=MicrosoftTeams) modules)

The following modules are currently not supported, because the don't implement
the certificate based login.:

- MSOL ([MSOnline](https://www.powershellgallery.com/packages?q=MSOnline) module)
- Security & Compliance (Part of the [ExchangeOnlineManagement](https://www.powershellgallery.com/packages?q=ExchangeOnlineManagement) module)

## Features

Example workflow to use this module:

````powershell
# Register the enterprise application. A UI prompt will query for the login.
Register-MicrosoftOnlineAutomation -Name 'Contoso' -Verbose

# Now, we can check if the application is registered.
Get-MicrosoftOnlineTenant -Name 'Contoso'

# A connection string can be generated and afterwards be imported on an other
# machine. The connection string contains sensitive information and must be
# protected.
$connectionString = Get-MicrosoftOnlineTenantConnectionString -Name 'Contoso'
Add-MicrosoftOnlineTenant -Name 'ContosoClone' -ConnectionString $connectionString

# Finally, we use the connect command or on of the aliases (aad, o365, m365) to
# connect to the scope we current need. Not specifying any scopes will connect
# to all supported scopes.
Connect-MicrosoftOnline -Name 'Contoso' -Scope 'Exchange', 'SharePoint'
```

## Versions

Please find all versions in the [GitHub Releases] section and the release notes
in the [CHANGELOG.md] file.

## Installation

Use the following command to install the module from the [PowerShell Gallery],
if the PackageManagement and PowerShellGet modules are available:

```powershell
# Download and install the module
Install-Module -Name 'MicrosoftOnlineFever'
```

Alternatively, download the latest release from GitHub and install the module
manually on your local system:

1. Download the latest release from GitHub as a ZIP file: [GitHub Releases]
2. Extract the module and install it: [Installing a PowerShell Module]

## Requirements

The following minimum requirements are necessary to use this module, or in other
words are used to test this module:

* Windows 10
* Windows PowerShell 5.1

## Contribute

Please feel free to contribute to this project. For the best development
experience, please us the following tools:

* [Visual Studio Code] with the [PowerShell Extension]
* [Pester], [PSScriptAnalyzer], [InvokeBuild], [InvokeBuildHelper] modules

[PowerShell Gallery]: https://psgallery.arcade.ch/feeds/powershell/ArcadeFramework
[CHANGELOG.md]: CHANGELOG.md

[Visual Studio Code]: https://code.visualstudio.com/
[PowerShell Extension]: https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell

[Pester]: https://www.powershellgallery.com/packages/Pester
[PSScriptAnalyzer]: https://www.powershellgallery.com/packages/PSScriptAnalyzer
[InvokeBuild]: https://www.powershellgallery.com/packages/InvokeBuild
[InvokeBuildHelper]: https://www.powershellgallery.com/packages/InvokeBuildHelper
