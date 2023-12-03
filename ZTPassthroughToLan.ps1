#Preliminary testing has been successful, still needs more testing. Added to the ledger for infield testing.
$switchName = "Microsoft Teredo Tunneling Adapter"
$combinedOutput = "vEthernet ($switchName)"
$ztnetwork = "172.28.0.0/16"
$ztsubnet = "16"
$ztipbaseforswitch = "172.28.50."
$ztiprangeforswitch = $ztipbaseforswitch + (Get-Random -Minimum 10 -Maximum 254)
$restartRequired = Test-PendingReboot
#Hyper-V enabling
$Name = "Hyper-V feature Install?"
$fuction = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($fuction)) {
    Start-Sleep -Seconds 1
    $fuction = "n"
}
if ($fuction.ToLower() -eq "y") {
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
} else {}
#Restart-Computer
$Name = "System Reboot Prompt"
$fuction = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($fuction)) {
    Start-Sleep -Seconds 1
    $fuction = "n"
}
if ($fuction.ToLower() -eq "y") {
shutdown /t 30 /r /c "Critical Windows Security Update is about to be installed. The system will REBOOT in 30 seconds. Please save your work and close all the windows. We are sorry for the inconvenience."
} else {}
##Nat setup
$Name = "NAT setup?"
$fuction = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($fuction)) {
    Start-Sleep -Seconds 1
    $fuction = "n"
}
if ($fuction.ToLower() -eq "y") {
    New-VMSwitch -SwitchName $switchName -SwitchType Internal
    $adapter = Get-NetAdapter -Name $combinedOutput
    $ifIndex = $adapter.ifIndex
    New-NetIPAddress -IPAddress $ztiprangeforswitch -PrefixLength $ztsubnet -InterfaceIndex $ifIndex -Confirm:$false | Out-Null
    New-NetNat -Name ipv6-tunneling -InternalIPInterfaceAddressPrefix $ztnetwork -Confirm:$false | Out-Null
} else {}
#CleanUP
$Name = "NAT and Hyper-V Removal?"
$fuction = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($fuction)) {
    Start-Sleep -Seconds 1
    $fuction = "n"
}
if ($fuction) {
    Get-VMSwitch -Name $switchName | Remove-VMSwitch -Force
    $natNetworkName = "ipv6-tunneling"
    Remove-NetNat -Name $natNetworkName -Confirm:$false
    Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
} else {}
