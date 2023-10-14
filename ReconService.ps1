function Get-ServiceDetails {
    param (
        [string]$serviceName
    )

    $matchingServices = Get-Service | Where-Object { $_.DisplayName -like "*$serviceName*" -or $_.ServiceName -like "*$serviceName*" }

    if ($matchingServices.Count -eq 0) {
        Write-Host "No matching services found."
    } else {
        $serviceDetails = @()

        foreach ($service in $matchingServices) {
            $serviceDetail = [PSCustomObject]@{
                'Display Name' = $service.DisplayName
                'Startup Type' = $service.StartType
                'Status' = $service.Status
                'Path to Executable' = (Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq $service.Name }).PathName
            }

            $serviceDetails += $serviceDetail
        }

        $serviceDetails | ForEach-Object {
            Write-Host "Service Name: $($matchingServices.ServiceName)" -ForegroundColor Green
            Write-Host "Display Name: $($_.'Display Name')"
            Write-Host "Startup Type: $($_.'Startup Type')"
            Write-Host "Status: $($_.'Status')"
            Write-Host "Path to Executable: $($_.'Path to Executable')" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

do {
    $serviceName = Read-Host "Enter a service name (or part of it) to search or 'qq' to quit:"

    if ($serviceName -eq 'qq') {
        break
    }

    Get-ServiceDetails -serviceName $serviceName
} while ($true)
