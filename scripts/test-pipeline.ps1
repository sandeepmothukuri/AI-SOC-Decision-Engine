<#
.SYNOPSIS
    SOC Stack Pipeline & Health Check for Windows PowerShell.
.DESCRIPTION
    Checks reachability of Wazuh, TheHive, Cortex, Shuffle, MISP, Ollama, and AI SOC Decision Engine.
#>

$ErrorActionPreference = "Continue"

function Write-Pass([string]$Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Fail([string]$Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Warn([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== AI SOC Decision Engine Pipeline Health Check ===" -ForegroundColor Cyan
Write-Host ""

function Check-ServiceEndpoint([string]$Name, [string]$Url, [int]$ExpectedStatus = 200) {
    try {
        # Ignore SSL certificate validation errors for local self-signed setups
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.ServerCertificateCustomValidationCallback = { $true }
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(3)
        $response = $client.GetAsync($Url).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode
        if ($statusCode -eq $ExpectedStatus -or ($statusCode -ge 200 -and $statusCode -lt 400)) {
            Write-Pass "$Name ($Url) -> HTTP $statusCode"
        } else {
            Write-Warn "$Name ($Url) -> HTTP $statusCode (Expected $ExpectedStatus)"
        }
    } catch {
        Write-Fail "$Name ($Url) -> Unreachable: $($_.Exception.Message)"
    }
}

Write-Host "--- Core Services ---" -ForegroundColor Cyan
Check-ServiceEndpoint "AI Engine Health" "http://localhost:8888/health" 200
Check-ServiceEndpoint "Ollama API" "http://localhost:11434/api/tags" 200
Check-ServiceEndpoint "TheHive 5" "http://localhost:9000" 200
Check-ServiceEndpoint "Cortex" "http://localhost:9001" 200
Check-ServiceEndpoint "Shuffle SOAR" "http://localhost:3001" 200
Check-ServiceEndpoint "MISP CTI" "http://localhost:8080" 200
Check-ServiceEndpoint "Wazuh Dashboard" "https://localhost:443" 200
Check-ServiceEndpoint "Wazuh API" "https://localhost:55000" 401

Write-Host ""
Write-Host "--- Docker Containers ---" -ForegroundColor Cyan
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $containers = @("wazuh-manager", "wazuh-indexer", "wazuh-dashboard", "thehive", "cortex", "cassandra", "shuffle-backend", "shuffle-frontend", "ollama", "ai-engine", "misp")
    $running = docker ps --format "{{.Names}}"
    foreach ($c in $containers) {
        if ($running -contains $c) {
            Write-Pass "Container: $c"
        } else {
            Write-Warn "Container: $c (not running)"
        }
    }
} else {
    Write-Warn "Docker CLI not detected in current PATH."
}
Write-Host ""
