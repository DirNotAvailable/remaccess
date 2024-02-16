#This is script that leaves the network if it is joined, and joins if
#it is in being left state. When it joins it also renames the 
#adapter created due to joining. And also modification are made to 
#firewall rule to add the traffic to private firewall chain.

$zerotiercli = "C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe"
$param1 = "-q"
$NetworkID = "52b337794f5f54e7"

# Run the command to list networks
$output = & $zerotiercli $param1 listnetworks

# Check if the specified NetworkID is found in the output
if ($output -match $NetworkID) {
    # If found, run the command to leave the network
    & $zerotiercli $param1 leave $NetworkID
}
else {
    # If not found, run the command to join the network
    & $zerotiercli $param1 join $NetworkID allowDefault=1

    # Rename adapter
    $adapterNameToRename = "Zerotier*"
    $newAdapterName = "Microsoft Teredo IPv6 Tunneling Interface"
    $maxRetries = 3
    $retryCount = 0
    while ($retryCount -lt $maxRetries) {
        try {
            $adapter = Get-NetAdapter -Name $adapterNameToRename
            if ($adapter) {
                Rename-NetAdapter -InputObject $adapter -NewName $newAdapterName
                break  # Exit the loop on success
            } else {
                break  # Exit the loop if the adapter is not found
            }
        } catch {
            $retryCount++
            Start-Sleep -Seconds 5  # Add a delay before the next retry
        }
    }

    # Update firewall rules
    $AppNamePattern = "ZeroTier*"
    $Rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like $AppNamePattern }
    $ProfileType = "Private"
    if ($Rules.Count -gt 0) {
        foreach ($Rule in $Rules) {
            $Rule.Profile = $ProfileType
            Set-NetFirewallRule -InputObject $Rule | Out-Null
        }
    }
}