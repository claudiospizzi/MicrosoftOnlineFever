<#
    .SYNOPSIS
        Import a raw data Base64 certificate into the certificate store.

    .DESCRIPTION
        To import a certificate into the certificate store. The raw data is
        directly imported into the store.

    .EXAMPLE
        PS C:\> Export-MicrosoftOnlineCertificate -CertStore 'Cert:\CurrentUser\My' -CertBase64 $certBase64
        Import the Base64 certificate in to the store.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Import-MicrosoftOnlineCertificate
{
    [CmdletBinding()]
    param
    (
        # Path to the certificate store.
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ })]
        [System.String]
        $CertStore,

        # Base64 representation of the certificate raw data.
        [Parameter(Mandatory = $true)]
        [System.String]
        $CertBase64
    )

    $certRawData = [System.Convert]::FromBase64String($CertBase64)
    $certX509    = [System.Security.Cryptography.X509Certificates.X509Certificate]::new($certRawData)
    $certX509v2  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certX509)

    try
    {
        $certStoreX509 = Get-Item -Path $CertStore
        if ($certStoreX509 -isnot [System.Security.Cryptography.X509Certificates.X509Store])
        {
            throw "The path $CertStore is not a certificate store!"
        }

        $certStoreX509.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $certStoreX509.Add($certX509v2)
    }
    catch
    {
        if ($null -ne $certStoreX509 -and $certStoreX509 -is [System.Security.Cryptography.X509Certificates.X509Store])
        {
            $certStoreX509.Close()
            $certStoreX509.Dispose()
        }
    }
}
