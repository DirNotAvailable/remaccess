function Get-ServiceDetails {
    param (
        [string]$serviceName
    )

    $matchingServices = Get-Service | Where-Object { $_.DisplayName -like "*$serviceName*" -or $_.ServiceName -like "*$serviceName*" }
    $uniqueServiceNames = $matchingServices | Select-Object -ExpandProperty ServiceName -Unique

    if ($uniqueServiceNames.Count -eq 0) {
        Write-Host "No matching services found."
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
            Write-Host "Service Name: $($_.'Service Name')" -ForegroundColor Green
            Write-Host "Display Name: $($_.'Display Name')"
            Write-Host "Startup Type: $($_.'Startup Type')" -ForegroundColor Green
            Write-Host "Status: $($_.'Status')" -ForegroundColor Green
            Write-Host "Path to Executable: $($_.'Path to Executable')" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

do {
    $serviceName = Read-Host "Enter a service name (or part of it) to search or 'q' to quit:"

    if ($serviceName -eq 'q') {
        break
    }

    Get-ServiceDetails -serviceName $serviceName
} while ($true)
