<#
.SYNOPSIS
    Full SOC lab deployment script for Windows PowerShell.
.DESCRIPTION
    Deploys Wazuh, Suricata, Zeek, TheHive, Cortex, Shuffle, MISP, Ollama and AI SOC Decision Engine.
#>

param(
    [string]$SensorInterface = $env:SOC_SENSOR_INTERFACE
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

# 1. Check requirements
Write-Log "Checking system requirements..."
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "Docker is not installed or not in PATH. Please install Docker Desktop."
}

# Check docker compose
$composeCmd = "docker compose"
try {
    & docker compose version | Out-Null
} catch {
    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        $composeCmd = "docker-compose"
    } else {
        Write-Err "Docker Compose not found. Please install Docker Compose v2."
    }
}

# 2. Create SOC docker network
Write-Log "Ensuring Docker network 'soc-network' exists..."
$existingNet = docker network ls --filter name=soc-network --format "{{.Name}}"
if (-not $existingNet) {
    docker network create soc-network
    Write-Log "Created network: soc-network"
} else {
    Write-Warn "Network 'soc-network' already exists."
}

# 3. Create sensor directories
$repoRoot = Split-Path -Parent $PSScriptRoot
$zeekLogs = Join-Path $repoRoot "network-sensors\zeek\logs"
$suricataLogs = Join-Path $repoRoot "network-sensors\suricata\logs"

if (-not (Test-Path $zeekLogs)) { New-Item -ItemType Directory -Path $zeekLogs -Force | Out-Null }
if (-not (Test-Path $suricataLogs)) { New-Item -ItemType Directory -Path $suricataLogs -Force | Out-Null }

# 4. Service Deployments
$dockerDir = Join-Path $repoRoot "docker"

function Deploy-ComposeService([string]$name, [string]$file) {
    Write-Log "Deploying $name..."
    $filePath = Join-Path $dockerDir $file
    if (-not (Test-Path $filePath)) {
        Write-Warn "File not found: $filePath. Skipping $name."
        return
    }
    docker compose -f $filePath up -d
    Write-Log "$name deployment command completed."
}

Deploy-ComposeService "Wazuh (SIEM / EDR)" "docker-compose.wazuh.yml"

if ($SensorInterface) {
    $env:SOC_SENSOR_INTERFACE = $SensorInterface
    Deploy-ComposeService "Network Sensors (Suricata + Zeek on $SensorInterface)" "docker-compose.network-sensors.yml"
} else {
    Write-Warn "SOC_SENSOR_INTERFACE not set. Skipping network sensor deployment."
    Write-Warn "To enable: `$env:SOC_SENSOR_INTERFACE = 'Ethernet'; .\scripts\deploy.ps1"
}

Deploy-ComposeService "TheHive 5 + Cortex" "docker-compose.thehive.yml"
Deploy-ComposeService "Shuffle (SOAR)" "docker-compose.shuffle.yml"
Deploy-ComposeService "MISP (Threat Intel)" "docker-compose.misp.yml"
Deploy-ComposeService "Ollama (Local LLM)" "docker-compose.ollama.yml"

Write-Log "All core SOC services deployment triggered!"
Write-Log "Run '.\scripts\setup-ollama.ps1' to pull the default LLaMA 3 model."
Write-Log "Run '.\scripts\test-pipeline.ps1' to verify service health."
