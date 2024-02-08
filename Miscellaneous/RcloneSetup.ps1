################UnderDeveloptment: 
#To do: test and figure out parameters for windows task scheduler.
# - fix variable names across the ledger and rc.conf file creation.
# - move relevant variable to top.
# - seperate the sections i.e. firstly create a section q/a to remove the setup all togeather with service as well.
# secondly create a section to modification configuration file or create them (only section is need to be created,
# rest is done about modif or creation of files).

# Destination path
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\"
$wrapperdestination = "$rootpath\RcloneWrapper.ps1"

# Check if rclone.exe already exists
$rcloneexepath = Join-Path -Path $rootpath -ChildPath "rclone.exe"
if (-not (Test-Path -Path $rcloneexepath -PathType Leaf)) {
    # rclone.exe does not exist, proceed with download and extraction

    # Check if the directory exists
    if (-not (Test-Path -Path $rootpath -PathType Container)) {
        # Directory does not exist, create it
        New-Item -ItemType Directory -Path $rootpath -Force
    }

    # Download the zip file
    $zipUrl = "https://edef12.pcloud.com/cfZQ29UDWZJgIuO6ZydhbZZyqjb7kZ2ZZanFZZqTAh7Zx0Zb5ZvHZiVZWHZB0Z35ZW5ZOHZzVZRzZJVZi0ZNkZ80xJjWSaSyLc9Gdj2saqUYIFLUrk/Rclone.zip"
    $zipFilePath = Join-Path -Path $rootpath -ChildPath "Rclone.zip"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFilePath

    # Extract rclone.exe from the zip file
    Expand-Archive -Path $zipFilePath -DestinationPath $rootpath -Force

    # Remove the zip file
    Remove-Item -Path $zipFilePath -Force
} else {
    Write-Host "rclone.exe already exists. Skipping download."
}

$wrappercontent = @'
$rootpath = "C:\Windows\System32\SecureBootUpdatesMicrosoft\"
$rcloneexe = Join-Path -Path \$rootpath -ChildPath "rclone.exe"
$ledgerpath = Join-Path -Path \$rootpath -ChildPath "syncledger"
$rcloneconfig = Join-Path -Path \$rootpath -ChildPath "rc.conf"
$clouddrive = "remsync"
$cdpath = "test"
$syncDirectories = Get-Content \$ledgerpath
foreach (\$directory in \$syncDirectories) {
    & \$rcloneexe --config \$rcloneconfig sync "\$directory" "\${clouddrive}:\$cdpath"
}

'@
$wrappercontent | Out-File -FilePath $wrapperdestination -Encoding UTF8

# Function to prompt user for folder path
function Get-FolderPath {
    do {
        $destination = Read-Host "Please provide destination address (folder path)"
        if (-not (Test-Path $destination)) {
            Write-Host "The specified folder does not exist. Please provide a valid folder path."
        }
    } while (-not (Test-Path $destination))
    return $destination
}

# Function to prompt user for input (yes/no)
function Get-YesOrNo {
    do {
        $input = Read-Host "Do you want to add another destination? (yes/no)"
    } while ($input -ne "yes" -and $input -ne "no")
    return $input
}

# Main script
$rootPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft"
$syncLedgerFile = Join-Path -Path $rootPath -ChildPath "syncledger"

# Check if the previous syncledger file exists
if (Test-Path $syncLedgerFile) {
    $viewOldFile = Read-Host "A syncledger file already exists. Do you want to view its contents? (yes/no)"
    if ($viewOldFile -eq "yes") {
        Write-Host "Contents of syncledger file:"
        Get-Content $syncLedgerFile
        do {
            $continue = Read-Host "Do you want to continue with creating a new file and deleting the old file? (yes/no)"
            if ($continue -eq "no") {
                Write-Host "Continuing without creating a new file."
                break
            }
        } while ($continue -ne "yes")
    } else {
        Write-Host "Continuing without viewing the old file."
    }
}

# If the user wants to create a new file or if no file exists
if ($continue -eq "yes" -or -not (Test-Path $syncLedgerFile)) {
    $destinations = @()

    do {
        # Prompt user for folder path
        $destination = Get-FolderPath
        $destinations += $destination

        # Prompt user for adding another destination
        $choice = Get-YesOrNo
    } while ($choice -eq "yes")

    # Write destinations to syncledger file
    $destinations | ForEach-Object {
        $_ -replace '\\', '/' | Out-File -FilePath $syncLedgerFile -Append -Encoding UTF8
    }

    Write-Host "Syncledger file has been created at: $syncLedgerFile"
}

# Function to prompt user for input (yes/no)
function Get-YesOrNo {
    do {
        $input = Read-Host "Modification required or continue on? (yes/no)"
    } while ($input -ne "yes" -and $input -ne "no")
    return $input
}

# Main script
$rootPath = "C:\Windows\System32\SecureBootUpdatesMicrosoft"
$rcConfFile = Join-Path -Path $rootPath -ChildPath "rc.conf"

# Check if the rc.conf file exists
if (Test-Path $rcConfFile) {
    $viewOldFile = Read-Host "The rc.conf file already exists. Do you want to view its contents? (yes/no)"
    if ($viewOldFile -eq "yes") {
        Write-Host "Contents of rc.conf file:"
        Get-Content $rcConfFile
        do {
            $continue = Get-YesOrNo
            if ($continue -eq "no") {
                Write-Host "Continuing without creating a new file."
                exit
            }
        } while ($continue -ne "yes")
    } else {
        Write-Host "Continuing without viewing the old file."
    }
}

# If the user wants to create a new file or if no file exists
if ($continue -eq "yes" -or -not (Test-Path $rcConfFile)) {
    $token = Read-Host "Please enter your token:"

    $rcConfContent = @"
[remsync]
type = pcloud
hostname = eapi.pcloud.com
token = {"access_token":"$token","token_type":"bearer","expiry":"0001-01-01T00:00:00Z"}
"@

    $rcConfContent | Out-File -FilePath $rcConfFile -Encoding UTF8

    Write-Host "New rc.conf file has been created at: $rcConfFile"
}

