# ============================================================
# AVOS AI - Unified Launch Script
# Usage: .\run_avos.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  AVOS AI - Security Platform            " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# -- Step 1: Check Python ------------------------------------------------------
Write-Host "[1/4] Checking Python environment..." -ForegroundColor Yellow
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $python = $cmd
            Write-Host "      Found: $ver" -ForegroundColor Green
            break
        }
    } catch { }
}
if (-not $python) {
    Write-Host "      ERROR: Python 3 not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}

# -- Step 2: Check Node / npm --------------------------------------------------
Write-Host "[2/4] Checking Node.js environment..." -ForegroundColor Yellow
try {
    $nodeVer = & node --version 2>&1
    $npmVer  = & npm --version 2>&1
    Write-Host "      Node: $nodeVer  npm: $npmVer" -ForegroundColor Green
} catch {
    Write-Host "      ERROR: Node.js not found. Install from https://nodejs.org" -ForegroundColor Red
    exit 1
}

# -- Step 3: Install UI dependencies if needed ---------------------------------
Write-Host "[3/4] Checking UI dependencies..." -ForegroundColor Yellow
$uiDir = Join-Path $ProjectRoot "ui"
if (-not (Test-Path (Join-Path $uiDir "node_modules\electron"))) {
    Write-Host "      Installing npm packages (first run may take a few minutes)..." -ForegroundColor Yellow
    Push-Location $uiDir
    & npm install --legacy-peer-deps
    Pop-Location
    Write-Host "      npm install complete." -ForegroundColor Green
} else {
    Write-Host "      Dependencies already installed." -ForegroundColor Green
}

# -- Step 4: Start Backend (Python CSO) ----------------------------------------
Write-Host "[4/4] Launching AVOS backend (CSO)..." -ForegroundColor Yellow
Write-Host "      The Python backend will start in a new window." -ForegroundColor Gray
Write-Host "      It serves HTTP REST on :8765 and gRPC on :50051" -ForegroundColor Gray

$backendProcess = Start-Process -FilePath $python `
    -ArgumentList "-m", "core.cso.orchestrator" `
    -WorkingDirectory $ProjectRoot `
    -PassThru `
    -WindowStyle Normal

Write-Host "      Backend PID: $($backendProcess.Id)" -ForegroundColor Green

# Give the backend 3 seconds to initialize
Start-Sleep -Seconds 3

# -- Step 5: Start Frontend (Electron + React) ---------------------------------
Write-Host ""
Write-Host "Launching AVOS UI (Electron + React)..." -ForegroundColor Cyan
Write-Host "The dashboard will open in a new window." -ForegroundColor Gray
Write-Host ""
Write-Host "To stop everything, close this PowerShell window." -ForegroundColor DarkGray
Write-Host ""

Push-Location $uiDir
try {
    & npm run dev
} finally {
    # Cleanup: kill backend when UI exits
    Pop-Location
    Write-Host ""
    Write-Host "UI closed. Stopping backend (PID $($backendProcess.Id))..." -ForegroundColor Yellow
    try { Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
    Write-Host "Done." -ForegroundColor Green
}
