# Automated Windows Cleanup & Update Script with Logging & Scheduling
# Run as Administrator

$logPath = "C:\Users\aslan\pyscripts\logs"
$logFile = "$logPath\system_cleanup_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"

# Ensure the log directory exists
if (!(Test-Path -Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}

# Function to log output
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
    Write-Host $message
}

Write-Log "Starting System Cleanup and Update..."

# Ensure Windows Update Module is Installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Log "Installing PSWindowsUpdate module..."
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser
}

# Force Windows Update Check & Install
Write-Log "Checking for Windows Updates..."
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot | Out-File -Append -FilePath $logFile

# Run Disk Cleanup (Silent Mode)
Write-Log "Running Disk Cleanup..."
cleanmgr /sagerun:1 | Out-File -Append -FilePath $logFile

# Clear Temp Files, Windows Logs, and Cache
Write-Log "Deleting Temp Files..."
Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\LogFiles\*" -Force -Recurse -ErrorAction SilentlyContinue
Write-Log "Temporary files cleared."

Write-Log "Enabling Storage Sense for Automatic Cleanup..."
$StorageSense = Get-StorageSense
if ($StorageSense -eq $null) {
    Enable-StorageSense -ErrorAction SilentlyContinue
    Write-Log "Storage Sense enabled."
} else {
    Write-Log "Storage Sense is already enabled."
}

# Restart if Required
Write-Log "Checking if a restart is needed..."
$RebootPending = Get-WindowsUpdate | Where-Object {$_.RebootRequired -eq $true}

if ($RebootPending) {
    Write-Log "A restart is required. Restarting in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Log "No restart required. Cleanup and updates complete!"
}

# Schedule Task to Run Every 5 Days
Write-Log "Creating Scheduled Task to Run Every 5 Days..."
$taskName = "SystemCleanupTask"

# Remove existing task if it exists
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Define action and trigger
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$PSScriptRoot\system_cleanup.ps1`" -ExecutionPolicy Bypass"
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 5 -At 3AM
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description "Automated system cleanup and updates every 5 days."

# Register the task
Register-ScheduledTask -TaskName $taskName -InputObject $task
Write-Log "Scheduled Task Created. Next run in 5 days."
