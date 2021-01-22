
$cert = Get-Item -Path Cert:\CurrentUser\My\94B1E1FDD9B986BF00B81650809D0A013EF40F9A
$applicationId = '45920d58-e4ca-4a55-a6f0-eacf6fccef47'
$applicationId = 'b7d1622a-20cb-4747-ad59-75b0e4da91c9'
$oAuthURI = 'https://login.microsoftonline.com/{0}/oauth2/token' -f '5f36d76e-9089-4ef3-94fc-d1758088e39a'

# $cert = Get-Item -Path Cert:\CurrentUser\My\092BF0D23B493A893530494E24D37846A8B1C4CC
# $applicationId = '77872b50-f121-4fc9-b74e-4cefd271fae4'
# $oAuthURI = 'https://login.microsoftonline.com/{0}/oauth2/token' -f 'b49dfab2-684e-48fa-b6e8-a30ef0115b38'

$ClientCert = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($ApplicationId, $Cert)
$authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($oAuthURI)
$task = $authContext.AcquireTokenAsync('https://management.azure.com/', $ClientCert)

$Token = ($task).Result.AccessToken
$Token = "Bearer $Token"
$Token

