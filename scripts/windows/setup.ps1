<#
.SYNOPSIS
  One-time setup of the privileged side of mcp-threatintel on Windows.
  Run from an ELEVATED PowerShell in the repository root:

      powershell -ExecutionPolicy Bypass -File scripts\windows\setup.ps1

  - creates C:\ProgramData\threatintel (responder.db, admin.token, quarantine, backup)
  - restricts it to Administrators + SYSTEM (by SID, works in any OS language),
    so the unprivileged MCP server cannot read the admin token or the action DB
  - creates the admin token and, if missing, an AGENT_TOKEN in .env
#>
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an elevated (Administrator) PowerShell.'
}

$dataDir = Join-Path $env:ProgramData 'threatintel'
foreach ($d in @($dataDir, "$dataDir\quarantine", "$dataDir\backup")) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18) only, no inheritance from ProgramData
& icacls $dataDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "icacls failed on $dataDir" }
Write-Host "[ok] $dataDir restricted to Administrators and SYSTEM"

$adminToken = Join-Path $dataDir 'admin.token'
if (-not (Test-Path $adminToken)) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ($bytes | ForEach-Object { $_.ToString('x2') }) -join '' | Set-Content -Path $adminToken -Encoding ascii -NoNewline
    Write-Host "[ok] admin token created at $adminToken"
} else {
    Write-Host "[ok] admin token already exists"
}

$envFile = Join-Path (Get-Location) '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path (Get-Location) '.env.example') $envFile
    Write-Host "[ok] .env created from .env.example - edit ABUSECH_API_KEY and SCAN_PATHS"
}
$envText = Get-Content $envFile -Raw
if ($envText -match '(?m)^AGENT_TOKEN=\s*$') {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $agentToken = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $envText = $envText -replace '(?m)^AGENT_TOKEN=\s*$', "AGENT_TOKEN=$agentToken"
    [IO.File]::WriteAllText($envFile, $envText, (New-Object Text.UTF8Encoding($false)))  # UTF-8, no BOM
    Write-Host "[ok] AGENT_TOKEN generated in .env"
} else {
    Write-Host "[ok] AGENT_TOKEN already set in .env"
}

Write-Host ''
Write-Host 'Next (elevated terminal):   .venv\Scripts\threatintel-responder'
Write-Host 'Approvals (elevated):       .venv\Scripts\threatintel-approve list'
