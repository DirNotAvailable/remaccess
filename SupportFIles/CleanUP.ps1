$psreadlineFolderPath = Join-Path $env:USERPROFILE 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
if (Test-Path -Path $psreadlineFolderPath -PathType Container) {
    $files = Get-ChildItem -Path $psreadlineFolderPath
    if ($files.Count -gt 0) {
        Remove-Item -Path "$psreadlineFolderPath\*" -Force
    }
}
