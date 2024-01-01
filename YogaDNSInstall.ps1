# Define URLs and file paths
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$downloadUrl = 'https://github.com/DirNotAvailable/remaccess/releases/download/v1.0.0/YogaDNS.zip'
$tempZipPath = "$env:TEMP\YogaDNS.zip"
$installPath = 'C:\Program Files (x86)'
$sys32Path = 'C:\Windows\System32\drivers'
$serviceConfigPath = Join-Path $installPath 'YogaDNS\ServiceConfiguration.xml'

##Clean Up process
$Name = "Removal of YogaDNS"
$pwdst = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Proceeding with $Name..."
		# Check if an old installation is present
		$oldInstallationPath = Join-Path $installPath 'YogaDNS'
		if (Test-Path $oldInstallationPath) {
			Write-Host 'Old installation found. Removing...'

			# Execute unins000.exe for silent uninstallation
			sc.exe stop YogaDNS | Out-Null
			$uninstallExe = Join-Path $oldInstallationPath 'unins000.exe'
			Start-Process -FilePath $uninstallExe -ArgumentList '/VERYSILENT' -Wait | Out-Null

			# Remove the folder
			Remove-Item $oldInstallationPath -Recurse -Force
		}
} else {}

##Configuration section for YogaDNS Installation.
$Name = "Configuration of YogaDNS?"
$pwdst = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Proceeding with $Name"
	# Define the YogaDNS folder path
	$yogaDnsFolderPath = Join-Path $installPath 'YogaDNS'
	# Check if the YogaDNS folder exists
	if (Test-Path $yogaDnsFolderPath -PathType Container) {
		# Read and edit ServiceConfiguration.xml
		[xml]$configXml = Get-Content $serviceConfigPath
		# Display current nextdns_id and prompt for user input
		$currentNextDnsId = $configXml.YogaDnsProfile.DnsServer.nextdns_id
		$userInputId = Read-Host "Current nextdns_id is: $currentNextDnsId. Do you want to change it? (Y/N)"
		if ($userInputId -eq 'Y' -or $userInputId -eq 'y') {
			$newNextDnsId = Read-Host 'Enter the new nextdns_id:'
			$configXml.YogaDnsProfile.DnsServer.SetAttribute('nextdns_id', $newNextDnsId)
		}
		# Prompt for new nextdns_devname
		$newDevName = Read-Host 'Enter the new nextdns_devname (without spaces):'
		$configXml.YogaDnsProfile.DnsServer.SetAttribute('nextdns_devname', $newDevName)
		# Save the updated XML
		$configXml.Save($serviceConfigPath)
		Write-Host 'YogaDNS configuration updated.'
	} else {
		Write-Host 'Error: YogaDNS folder not found. Please make sure YogaDNS is installed.'
	}
} else {}

##Install of YogaDNS with configuration Included.
$Name = "Install of YogaDNS?"
$pwdst = Read-Host "Proceed With $Name (y/n)"
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
    Write-Host "Proceeding with $Name"
		# Check if an old installation is present
		$oldInstallationPath = Join-Path $installPath 'YogaDNS'
			if (Test-Path $oldInstallationPath) {
				Write-Host 'Old installation found. Removing...'
				# Execute unins000.exe for silent uninstallation
				sc.exe stop YogaDNS | Out-Null
				$uninstallExe = Join-Path $oldInstallationPath 'unins000.exe'
				Start-Process -FilePath $uninstallExe -ArgumentList '/VERYSILENT' -Wait | Out-Null
				# Remove the folder
				Remove-Item $oldInstallationPath -Recurse -Force
			}

		# Download and extract YogaDNS directly to the final location
		Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZipPath
		Expand-Archive -Path $tempZipPath -DestinationPath $installPath -Force

		# Copy DnsFltEngineDrv.sys to System32 drivers folder
		Copy-Item -Path (Join-Path $installPath 'YogaDNS\DnsFltEngineDrv.sys') -Destination $sys32Path -Force

		# Read and edit ServiceConfiguration.xml
		[xml]$configXml = Get-Content $serviceConfigPath

		# Display current nextdns_id and prompt for user input
		$currentNextDnsId = $configXml.YogaDnsProfile.DnsServer.nextdns_id
		$userInputId = Read-Host "Current nextdns_id is: $currentNextDnsId. Do you want to change it? (Y/N)"

		if ($userInputId -eq 'Y' -or $userInputId -eq 'y') {
			$newNextDnsId = Read-Host 'Enter the new nextdns_id:'
			$configXml.YogaDnsProfile.DnsServer.SetAttribute('nextdns_id', $newNextDnsId)
		}

		# Prompt for new nextdns_devname
		$newDevName = Read-Host 'Enter the new nextdns_devname (without spaces):'
		$configXml.YogaDnsProfile.DnsServer.SetAttribute('nextdns_devname', $newDevName)

		# Save the updated XML
		$configXml.Save($serviceConfigPath)

		# Execute reginstall.reg
		$regFile = Join-Path $installPath 'YogaDNS\reginstall.reg'
		& reg.exe IMPORT $regFile

		# Remove temporary files
		Remove-Item $tempZipPath -Force

		Write-Host 'YogaDNS installation and configuration completed.'
} else {}
