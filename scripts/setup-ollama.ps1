<#
.SYNOPSIS
    Pull and configure Ollama models for the AI SOC Decision Engine on Windows.
.DESCRIPTION
    Pulls llama3 or custom model into local Ollama instance and verifies generation.
#>

param(
    [string]$Model = "llama3",
    [string]$OllamaHost = $(if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST } else { "http://localhost:11434" })
)

$ErrorActionPreference = "Stop"

function Write-Log([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Err([string]$Message) {
    Write-Host "[-] $Message" -ForegroundColor Red
    exit 1
}

Write-Log "Checking Ollama status at $OllamaHost..."
$attempts = 0
$ready = $false
while (-not $ready) {
    try {
        $res = Invoke-RestMethod -Uri "$OllamaHost/api/tags" -Method Get -TimeoutSec 3 -ErrorAction Stop
        $ready = $true
    } catch {
        $attempts++
        if ($attempts -ge 30) {
            Write-Err "Ollama did not respond after 30 attempts. Make sure Ollama container or service is running."
        }
        Write-Host "Waiting for Ollama to become ready ($attempts/30)..."
        Start-Sleep -Seconds 2
    }
}

Write-Log "Ollama is online and reachable."
Write-Log "Pulling model '$Model' (this may take several minutes depending on network speed)..."

$pullBody = @{ name = $Model } | ConvertTo-Json
try {
    $pullRes = Invoke-RestMethod -Uri "$OllamaHost/api/pull" -Method Post -Body $pullBody -ContentType "application/json" -TimeoutSec 900
    Write-Log "Model '$Model' pulled successfully."
} catch {
    Write-Err "Failed to pull model '$Model': $_"
}

Write-Log "Testing generation with '$Model'..."
$testBody = @{
    model = $Model
    prompt = "Reply with exactly: READY"
    stream = $false
} | ConvertTo-Json

try {
    $genRes = Invoke-RestMethod -Uri "$OllamaHost/api/generate" -Method Post -Body $testBody -ContentType "application/json" -TimeoutSec 60
    Write-Log "Model output: $($genRes.response.Trim())"
    Write-Log "Model verification passed!"
} catch {
    Write-Warn "Generation test failed or timed out: $_"
}
