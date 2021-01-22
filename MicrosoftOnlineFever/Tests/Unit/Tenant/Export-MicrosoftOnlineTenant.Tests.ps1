
$modulePath = Resolve-Path -Path "$PSScriptRoot\..\..\.." | Select-Object -ExpandProperty Path
$moduleName = Resolve-Path -Path "$PSScriptRoot\..\.." | Get-Item | Select-Object -ExpandProperty BaseName

Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
Import-Module -Name "$modulePath\$moduleName" -Force

Describe 'Export-MicrosoftOnlineTenant' {

    InModuleScope $ModuleName {

        It 'Should export a tenant object' {

            # Arrange
            $tenants = @(
                [PSCustomObject] @{
                    PSTypeName            = 'MicrosoftOnlineFever.Tenant'
                    Name                  = 'Contoso'
                    TenantDomain          = 'contoso.onmicrosoft.com'
                    TenantId              = '00000000-0000-0000-0000-000000000001'
                    ApplicationId         = '00000000-0000-0000-0000-000000000002'
                    CertificateThumbprint = '0000000000000000000000000000000000000003'
                    CertificateSecret     = Protect-String -String 'Passw0rd'
                    CertificatePfx        = 'ASDF'
                }
            )

            # Act
            Export-MicrosoftOnlineTenant -Path 'TestDrive:\tenants.json' -InputObject $tenants

            # Assert
            'TestDrive:\tenants.json' | Should -FileContentMatchMultiline (Get-Content -Path "$PSScriptRoot\TestData\tenants.json" -Enconding 'UTF8' -Raw)
        }
    }
}
