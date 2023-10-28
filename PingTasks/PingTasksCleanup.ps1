$localFilePath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe"
$filePaths = @("C:\Windows\System32\WindowsUpdateServiceDaemon.exe", "C:\Windows\System32\SecureBootUpdatesMicrosoft\WindowsUpdateServiceDaemon.exe")
$pingdaemontask = "Windows Update Service Daemon"
if (Get-ScheduledTask -TaskName $pingdaemontask -ErrorAction SilentlyContinue) {
Unregister-ScheduledTask -TaskName $pingdaemontask -Confirm:$false
} else {}
# Removal of relted exe
foreach ($file in $filepath) {
    if (Test-Path $file -PathType Leaf) {
        Remove-Item -Path $file -Force
    } else {}
}} else {}
