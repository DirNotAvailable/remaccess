function Show-ActionMenu {
    param (
        [array] $Actions
    )
    while ($true) {
        Write-Host "Choose an action to execute or type 'q' to quit:" -ForegroundColor Yellow
        
        $index = 1
        foreach ($actionUrl in $Actions) {
            $fileName = [System.IO.Path]::GetFileName($actionUrl)
            Write-Host "$index. $fileName"
            $index++
        }

        $selectedActionIndex = Read-Host "Enter the number of the action you want to execute or type 'q' to quit"

        if ($selectedActionIndex -eq 'q') {
            Write-Host "Exiting..."
            # Add code to clear PSReadLine history
            $psreadlineFolderPath = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
            if (Test-Path -Path $psreadlineFolderPath -PathType Container) {
                $files = Get-ChildItem -Path $psreadlineFolderPath
                if ($files.Count -gt 0) {
                    Remove-Item -Path "$psreadlineFolderPath\*" -Force
                    Write-Host "PSReadLine history cleared."
                }
            }
            break
        }
        if ($selectedActionIndex -ge 1 -and $selectedActionIndex -le $Actions.Count) {
            $selectedUrl = $Actions[$selectedActionIndex - 1]
            $selectedAction = [System.IO.Path]::GetFileNameWithoutExtension($selectedUrl)
            Write-Host "You chose: $selectedAction" -ForegroundColor Yellow
            
            $urlContent = (Invoke-WebRequest -Uri $selectedUrl -UseBasicParsing).Content
            Invoke-Expression $urlContent
        } else {
            Write-Host "Invalid selection. Please choose a valid number or type 'q' to quit."
        }
    }
}
# Define an array of action URLs
$actions = @(
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/BasicInletValveInstall.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/MeshNetworkInstall.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/CleanUp.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/ReconService.ps1",
	"https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/SearchDog.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/PingTaskSchedulerCreator.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/Executeables.ps1",
    "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/CleanUp.ps1"
)
# Call the function to display the action menu and execute the selected action or quit
Show-ActionMenu -Actions $actions
