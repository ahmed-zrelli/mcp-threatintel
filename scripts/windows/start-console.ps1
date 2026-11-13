# Start the analyst console on this PC (split architecture): MCP server for Qwen,
# feed poller (pushes intel to the agent), the dashboard and the AI responder (decides the
# alerts the rules cannot handle), each in its own window. -LlmContext = llama-server -c.
# Nothing is installed or scheduled: close the windows to stop everything.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\start-console.ps1
#
# Needs the console bundle copied from the server into .\console\
#   scp -i <key> <user>@<server>:/etc/threatintel/console/* console\
param([switch]$NoPoller, [switch]$DashboardOnly, [switch]$PollerOnly, [switch]$NoAI, [int]$LlmContext = 8192)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$bundle = Join-Path $root "console"
foreach ($f in "console.env", "agent.token", "agent.crt", "admin.token") {
    if (-not (Test-Path (Join-Path $bundle $f))) { throw "missing console\$f - copy /etc/threatintel/console/* from the server first" }
}

# Settings for the child processes (they take precedence over .env, which keeps the feed API keys).
foreach ($line in Get-Content (Join-Path $bundle "console.env")) {
    if ($line -match '^\s*([A-Z_]+)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2].Trim() }
}
$env:AGENT_CA = Join-Path $bundle "agent.crt"
$env:ADMIN_TOKEN_FILE = Join-Path $bundle "admin.token"
$env:AGENT_TOKEN = (Get-Content (Join-Path $bundle "agent.token") -Raw).Trim()
$env:MCP_HOST = "127.0.0.1"
if (-not $env:DB_PATH) { $env:DB_PATH = Join-Path $root "data\threatintel.db" }

$py = Join-Path $root ".venv\Scripts"
function Start-Window($title, $exe, $argList) {
    $cmd = "`$host.UI.RawUI.WindowTitle='$title'; Set-Location '$root'; & '$py\$exe' $argList"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $cmd | Out-Null
}

Write-Host "Agent: $env:AGENT_ADDR (admin $env:ADMIN_ADDR)"
if ($PollerOnly) { Start-Window "Feed poller (pushes intel to the agent)" "mcp-threatintel-poller.exe" "--loop"; return }
if (-not $DashboardOnly) { Start-Window "MCP server (Qwen tools)" "mcp-threatintel.exe" "" }
if (-not $NoPoller -and -not $DashboardOnly) { Start-Window "Feed poller (pushes intel to the agent)" "mcp-threatintel-poller.exe" "--loop" }
Start-Window "Dashboard" "threatintel-console.exe" ""
if (-not $DashboardOnly -and -not $NoAI) {
    # AI responder: decides the alerts the rules cannot handle (needs llama-server; waits for it otherwise)
    Start-Window "AI responder (Qwen)" "threatintel-watch.exe" "--llm-context $LlmContext"
}
Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:3720"
Write-Host "Started. Dashboard: http://127.0.0.1:3720   MCP for the WebUI: http://127.0.0.1:3707/mcp"
