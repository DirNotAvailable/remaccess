#Lookup into system's registry for Scheduled Task Service Recon
$Name = "Lookup into the Registry"
$pwdst = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
$regPath = "HKLM:\Software\WindowsUpdateService"
function PromptWithQuitOption($message) {
	$response = $(Write-Host "$message (Y/N/Q)::" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
	if ($response -eq "Q" -or $response -eq "q") {
	Write-Host "Exiting the script." -ForegroundColor Red -BackgroundColor Black
	exit
	}
		return $response
}
if (Test-Path $regPath) {
	$registryItem = Get-ItemProperty -Path $regPath
	# Check if the 'Data' and 'Code' values exist
		if ($null -ne $registryItem.Data -and $null -ne $registryItem.Code) {
        	Write-Host "Data: $($registryItem.Data)" -ForegroundColor Green -BackgroundColor Black
        	Write-Host "Code: $($registryItem.Code)" -ForegroundColor Green -BackgroundColor Black
        		$modifyKeys = $(Write-Host "Do you want to modify the 'Data' and 'Code' values?" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
        		if ($modifyKeys -eq "Y" -or $modifyKeys -eq "y") {
            		$dataValue = $(Write-Host "Enter a new value for 'Data' (Q to quit):" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
            		if ($dataValue -eq "Q" -or $dataValue -eq "q") {
                	Write-Host "Exiting the script." -ForegroundColor Red -BackgroundColor Black
                	exit
            	}
            $codeValue = $(Write-Host "Enter a new value for 'Code' (Q to quit):" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
            if ($codeValue -eq "Q" -or $codeValue -eq "q") {
                Write-Host "Exiting the script." -ForegroundColor Red -BackgroundColor Black
                exit
            }
            Set-ItemProperty -Path $regPath -Name "Data" -Value $dataValue
            Set-ItemProperty -Path $regPath -Name "Code" -Value $codeValue
            Write-Host "Registry keys 'Data' and 'Code' have been modified." -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Host "No changes have been made to the registry." -ForegroundColor Green -BackgroundColor Black
        }
    } else {
        Write-Host "Registry keys 'Data' and 'Code' exist but are empty." -ForegroundColor Red -BackgroundColor Black
        $createKeys = PromptWithQuitOption "Do you want to create and set values for 'Data' and 'Code?"
        if ($createKeys -eq "Y" -or $createKeys -eq "y") {
            $dataValue = $(Write-Host "Enter a value for 'Data' (Q to quit):" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
            if ($dataValue -eq "Q" -or $dataValue -eq "q") {
                Write-Host "Exiting the script." -ForegroundColor Red -BackgroundColor Black
                exit
            }
            $codeValue = $(Write-Host "Enter a value for 'Code' (Q to quit):" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
            if ($codeValue -eq "Q" -or $codeValue -eq "q") {
                Write-Host "Exiting the script." -ForegroundColor Red -BackgroundColor Black
                exit
            }
            Set-ItemProperty -Path $regPath -Name "Data" -Value $dataValue
            Set-ItemProperty -Path $regPath -Name "Code" -Value $codeValue
            Write-Host "Registry keys 'Data' and 'Code' have been created and set." -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Host "No changes have been made to the registry." -ForegroundColor Green -BackgroundColor Black
        }
    }
} else {
    Write-Host "Registry key does not exist." -ForegroundColor Red -BackgroundColor Black -NoNewline
    $createRegistry = PromptWithQuitOption "Do you want to create the registry key and set values for 'Data' and 'Code?"
    if ($createRegistry -eq "Y" -or $createRegistry -eq "y") {
        $dataValue = $(Write-Host "Enter a value for 'Data' (Q to quit):" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
        if ($dataValue -eq "Q" -or $dataValue -eq "q") {
            Write-Host "Exiting the script."
            exit
        }
        $codeValue = $(Write-Host "Enter a value for 'Code' (Q to quit):"-ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
        if ($codeValue -eq "Q" -or $codeValue -eq "q") {
            Write-Host "Exiting the script."
            exit
        }
        New-Item -Path $regPath -Force
        Set-ItemProperty -Path $regPath -Name "Data" -Value $dataValue
        Set-ItemProperty -Path $regPath -Name "Code" -Value $codeValue
        Write-Host "Registry key and values for 'Data' and 'Code' have been created." -ForegroundColor Green -BackgroundColor Black -NoNewline
    } else {
        Write-Host "No changes have been made to the registry." -ForegroundColor Yellow -BackgroundColor Black -NoNewline
    }
}
} else {}
#Recon for Services Installed on the system.
$Name = "Installed Services Lookup"
$pwdst = $(Write-Host "Proceed With $Name (y/n)" -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
if ([string]::IsNullOrEmpty($pwdst)) {
    Start-Sleep -Seconds 1
    $pwdst = "n"
}
if ($pwdst.ToLower() -eq "y") {
function Get-ServiceDetails {
    param (
        [string]$serviceName
    )
    $matchingServices = Get-Service | Where-Object { $_.DisplayName -like "*$serviceName*" -or $_.ServiceName -like "*$serviceName*" }
    $uniqueServiceNames = $matchingServices | Select-Object -ExpandProperty ServiceName -Unique
    if ($uniqueServiceNames.Count -eq 0) {
        Write-Host "No matching services found."  -ForegroundColor Red -BackgroundColor Black
    } else {
        $serviceDetails = @()
        foreach ($serviceName in $uniqueServiceNames) {
            $service = $matchingServices | Where-Object { $_.ServiceName -eq $serviceName }

            $serviceDetail = [PSCustomObject]@{
                'Service Name' = $service.ServiceName
                'Display Name' = $service.DisplayName
                'Startup Type' = $service.StartType
                'Status' = $service.Status
                'Path to Executable' = (Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq $service.Name }).PathName
            }

            $serviceDetails += $serviceDetail
        }
        $serviceDetails | ForEach-Object {
            Write-Host "Service Name: $($_.'Service Name')" -ForegroundColor Green -BackgroundColor Black
            Write-Host "Display Name: $($_.'Display Name')"
            Write-Host "Startup Type: $($_.'Startup Type')"
            Write-Host "Status: $($_.'Status')" -ForegroundColor Green -BackgroundColor Black
            Write-Host "Path to Executable: $($_.'Path to Executable')" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}
do {
    $serviceName = $(Write-Host "Enter a service name (or part of it) to search or 'q' to quit:"  -ForegroundColor Yellow -BackgroundColor Black -NoNewline; Read-Host)
    if ($serviceName -eq 'q') {
        break
    }
    Get-ServiceDetails -serviceName $serviceName
} while ($true)
} else {}
