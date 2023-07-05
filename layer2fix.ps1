Get-NetAdapter -Name Zerotier*|Rename-NetAdapter -NewName Microsoft
$SwitchName = "Microsoft"
New-VMSwitch -SwitchName $SwitchName -SwitchType Internal
$netAdapter = Get-NetAdapter
$IPAddress = "172.28.2.0"
$PrefixLength = 16
New-NetIPAddress -IPAddress $IPAddress -PrefixLength $PrefixLength -InterfaceIndex $netAdapter.InterfaceIndex
$InternalIPInterfaceAddressPrefix = "$IPAddress/16"
$NatName = "MicrosoftNAT"
New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $InternalIPInterfaceAddressPrefix