<#
    .SYNOPSIS
        .

    .DESCRIPTION
        .

    .INPUTS
        .

    .OUTPUTS
        .

    .EXAMPLE
        PS C:\> Connect-MicrosoftOnlineAutomation
        .

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Connect-MicrosoftOnlineAutomation
{
    [CmdletBinding()]
    param
    (
        #
        [Parameter(Mandatory = $true)]
        [System.String]
        $ConnectionString,

        # Use the preview modules if available.
        [Parameter(Mandatory = $false)]
        [Switch]
        $UsePreviewModule
    )

    Test-MicrosoftOnlineModuleDependency -UsePreviewModule:$UsePreviewModule

    $tenantId, $applicationId, $certificateThumbprint, $certificatePfx = $ConnectionString.Split(':')

    if (-not (Test-Path "Cert:\CurrentUser\My\$certificateThumbprint"))
    {
        # ToDo: Import Pfx...
    }

    Connect-AzureAD -TenantId $tenantId -ApplicationId $applicationId -CertificateThumbprint $certificateThumbprint





    # https://docs.microsoft.com/en-us/powershell/azure/active-directory/signing-in-service-principal?view=azureadps-2.0
    # https://erjenrijnders.nl/2018/08/30/azuread-login-without-credentials-unattended/
}
