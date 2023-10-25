#This needs more work. Do not use for now.
$switchName = "Microsoft Teredo Tunneling Adapter"
$combinedOutput = "vEthernet ($switchName)"
$ztnetwork = "172.28.0.0/16"
$ztsubnet = "16"
$ztipbaseforswitch = "172.28.50."
$ztiprangeforswitch = $ztipbaseforswitch + (Get-Random -Minimum 10 -Maximum 254)
function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    } catch {}
 
    return $false
}
$restartRequired = Test-PendingReboot
#Installation of the function
$Name = "Installation of Hyper-V and related Settings to enable Lan Passthrough?"
$pwdst = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {

if ($restartRequired) {
    Write-Host "A restart is required to enable Hyper-V."
    exit
}
$hyperVFeatureStatus = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
if ($hyperVFeatureStatus.State -eq 'Enabled') {
    Write-Host "Hyper-V is already enabled."
} else {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
    Write-Host "Hyper-V has been enabled without a restart."
}
if (-not $restartRequired -and $hyperVFeatureStatus.State -ne 'Enabled') {
    New-VMSwitch -SwitchName $switchName -SwitchType Internal
    $adapter = Get-NetAdapter -Name $combinedOutput
    $ifIndex = $adapter.ifIndex
    New-NetIPAddress -IPAddress $ztiprangeforswitch -PrefixLength $ztsubnet -InterfaceIndex $ifIndex -Confirm:$false | Out-Null
    New-NetNat -Name ipv6-tunneling -InternalIPInterfaceAddressPrefix $ztnetwork -Confirm:$false | Out-Null
}
} else {}
#CleanUP
$Name = "Removal of Hyper-V and relative settings?"
$pwdst = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
$hyperVFeatureStatus = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
if ($hyperVFeatureStatus.State -eq 'Enabled') {
    Get-VMSwitch -Name $switchName | Remove-VMSwitch -Force
    $natNetworkName = "ipv6-tunneling"
    Remove-NetNat -Name $natNetworkName -Confirm:$false
    Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
    Write-Host "Hyper-V has been uninstalled without a restart."
} else {
    Write-Host "Hyper-V is not currently installed."
}
if ($restartRequired) {
    Write-Host "A restart is required to complete the uninstallation."
}
} else {}
