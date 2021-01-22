<#
    .SYNOPSIS
        Export a certificate from the certificate store to a raw data Base64.

    .DESCRIPTION
        To export a certificate from the certificate store into the raw data as
        Base64 representation, a pfx file is temporarly created.

    .EXAMPLE
        PS C:\> Export-MicrosoftOnlineCertificate -CertPath 'Cert:\CurrentUser\My\6B0D16E3BE458ED1CAA77747001A8F5567FD9751'
        Convert the specified certificate to Base64.

    .LINK
        https://github.com/claudiospizzi/MicrosoftOnlineFever
#>
function Export-MicrosoftOnlineCertificate2
{
    [CmdletBinding()]
    param
    (
        # Thumbprint of the certificate to export.
        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

        # The certificate store.
        [Parameter(Mandatory = $false)]
        [System.String]
        $CertStore = 'Cert:\CurrentUser\My'
    )

    $certPath = '{0}\{1}' -f $CertStore, $Thumbprint
    $filePath = [System.IO.Path]::GetTempFileName()

    Export-PfxCertificate -Cert $certPath -FilePath $filePath





    # $filePath = [System.IO.Path]::GetTempFileName()
    # $filePwd  = ConvertTo-SecureString -String (New-Guid) -AsPlainText -Force

    # try
    # {
    #     Export-PfxCertificate -Cert $CertPath -FilePath $filePath -Password $filePwd -Force | Out-Null

    #     $certX509    = [System.Security.Cryptography.X509Certificates.X509Certificate]::new($filePath, $filePwd)
    #     $certRawData = $certX509.GetRawCertData()
    #     $certBase64  = [System.Convert]::ToBase64String($certRawData)

    #     return $certBase64
    # }
    # finally
    # {
    #     Remove-Item -Path $filePath -Force -ErrorAction 'SilentlyContinue'
    # }
}
