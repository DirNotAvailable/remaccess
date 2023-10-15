$currentTime = Get-Date
$timeString = $currentTime.ToString("yyyy-MM-dd HH:mm:ss")
Add-Content -Path "C:/Users/sandbox/Desktop/timestamps.txt" -Value $timeString
