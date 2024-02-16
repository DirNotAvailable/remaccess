# Define the value to search for
$SearchValue = "ZeroTier One*"

# Define the registry path
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"

# Recursively search for the value in the registry
$Matches = Get-ChildItem -Path $RegistryPath -Recurse | 
    ForEach-Object {
        $properties = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($properties -and $properties.Name -like $SearchValue) {
            $properties
            Remove-ItemProperty -Path $_.PSPath -Name "Name" -ErrorAction SilentlyContinue
        }
    }

# Display the matches
if ($Matches) {
    Write-Host "Matches found and deleted:"
    $Matches | Format-Table -Property PSPath, Name, Type, Data -AutoSize
} else {
    Write-Host "No matches found."
}
