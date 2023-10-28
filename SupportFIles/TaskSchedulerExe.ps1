$urlfortask = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/AccessControl.ps1"
$urlforsshdmaint = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/OpenSSHConfigMaintenance.ps1"
$job1 = Start-Job -ScriptBlock {
    param($url)
    $scriptcontent = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
    if ($scriptcontent) {
        Invoke-Expression $scriptcontent
    }
} -ArgumentList $urlfortask
$job2 = Start-Job -ScriptBlock {
    param($url)
    $scriptcontent = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
    if ($scriptcontent) {
        Invoke-Expression $scriptcontent
        Start-Sleep 5
    }
} -ArgumentList $urlforsshdmaint
Wait-Job -Job $job1, $job2
$job1Result = Receive-Job -Job $job1
$job2Result = Receive-Job -Job $job2
Remove-Job -Job $job1, $job2
