<#
.SYNOPSIS
  Start the threatintel-watch notifier automatically (hidden) at every Windows logon.
  Run from a NORMAL PowerShell in the repository root (no administrator needed):

      powershell -ExecutionPolicy Bypass -File scripts\windows\install-watch-autostart.ps1 -McpUrl http://192.168.21.129:3707/mcp

  Remove it again:
      powershell -ExecutionPolicy Bypass -File scripts\windows\install-watch-autostart.ps1 -Uninstall

  It creates one Scheduled Task, "ThreatIntel Watch", for the current user only.
  Log: %LOCALAPPDATA%\threatintel\watch.log
#>
param(
    [string]$McpUrl = "http://192.168.21.129:3707/mcp",
    [string]$LlmUrl = "http://127.0.0.1:8080",
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$TaskName = 'ThreatIntel Watch'

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[ok] '$TaskName' removed"
    return
}

$repo = (Get-Location).Path
$pythonw = Join-Path $repo '.venv\Scripts\pythonw.exe'
if (-not (Test-Path $pythonw)) { Write-Error "run this from the repository root ($pythonw not found)" }

$action = New-ScheduledTaskAction -Execute $pythonw `
    -Argument "-m mcp_threatintel.watch.watcher --mcp-url $McpUrl --llm-url $LlmUrl" `
    -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description "mcp-threatintel alert notifier (no admin rights)" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "[ok] '$TaskName' installed and started: it now runs hidden at every logon."
Write-Host "     Server: $McpUrl   Model: $LlmUrl"
Write-Host "     Log:    $env:LOCALAPPDATA\threatintel\watch.log"
