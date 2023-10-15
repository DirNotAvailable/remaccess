#This script creates a schedule task that will run everytime the system is booted up.
#Purpose of this scirpt to get notified once a system comes online.
$filepath = "C:\Windows\System32\WindowsUpdateServiceDaemon.ps1"
$pingdaemontask = "Windows Update Service Daemon"
$regPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftUpdateServiceDaemon"
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
	}
#Removing Registry Keys
if (Test-Path $regPath) {
    Remove-Item -Path $regPath -Recurse -Force
}
} else {}
#Creation of the setup
$Name = "Creating a schedule task for Pinging"
$prompt = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($prompt.ToLower() -eq "y") {
if (Test-Path $regPath) {
    Remove-Item -Path $regPath -Recurse -Force | Out-Null
}
New-Item -Path $regPath -Force | Out-Null
$webhookValue = Read-Host "Enter a value for 'Webhook'"
$nameValue = Read-Host "Enter a value for 'Name'"
Set-ItemProperty -Path $regPath -Name 'Webhook' -Value $webhookValue
Set-ItemProperty -Path $regPath -Name 'Name' -Value $nameValue
$script = @'
$regPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftUpdateServiceDaemon"
$webhookUrl = (Get-ItemProperty -Path $regPath).Webhook
$message = "$((Get-ItemProperty -Path $regPath).Name) is Online"
$jsonPayload = @{
    content = $message
} | ConvertTo-Json
Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $jsonPayload -ContentType "application/json"
'@
$script | Set-Content -Path $filepath
$fileContent = Get-Content -Path $filePath
$fileContent = $fileContent -replace 'ToBeReplaced', $webhookUrl
Set-Content -Path $filePath -Value $fileContent
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
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
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
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\WindowsUpdateServiceDaemon.ps1"</Arguments>
      <WorkingDirectory>C:\Windows\System32</WorkingDirectory>
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