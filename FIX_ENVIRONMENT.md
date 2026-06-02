# 🔧 Fix Virtual Environment & Dependencies

## Your Current Issue

Your virtual environment is corrupted/misconfigured. It's looking for:
```
e:\Projects\Personal Projects\Antivirus\.venv\Scripts\python.exe
```

But your actual venv is at:
```
E:\Projects\Personal Projects\Avos Antivirus\.venv\
```

---

## ✅ SOLUTION: Recreate Virtual Environment

### Step 1: Deactivate Current Environment
```powershell
deactivate
```

### Step 2: Delete Old Virtual Environment
```powershell
# Go to parent directory
cd "E:\Projects\Personal Projects\Avos Antivirus"

# Remove old venv
Remove-Item -Recurse -Force .venv
```

### Step 3: Create Fresh Virtual Environment
```powershell
# Create new venv
python -m venv .venv

# Activate it
.venv\Scripts\Activate.ps1
```

### Step 4: Install All Dependencies
```powershell
# Navigate to Avos_AiAv
cd Avos_AiAv

# Upgrade pip first
python -m pip install --upgrade pip

# Install compatible protobuf versions
pip install protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Install all other dependencies
pip install -r requirements.txt
```

### Step 5: Verify Installation
```powershell
# Check Python
python --version

# Check protobuf
python -c "from google.protobuf import runtime_version; print('Protobuf OK')"

# Check grpc
python -c "import grpc; print('gRPC OK')"
```

### Step 6: Initialize Database
```powershell
python -m core.db.db_manager --init
```

### Step 7: Start Backend
```powershell
python -m core.cso.orchestrator
```

---

## Alternative: Use System Python (No Virtual Environment)

If you don't want to use a virtual environment:

### Step 1: Deactivate venv
```powershell
deactivate
```

### Step 2: Install Dependencies Globally
```powershell
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"

# Install compatible versions
pip install protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Install all dependencies
pip install -r requirements.txt
```

### Step 3: Run Normally
```powershell
python -m core.cso.orchestrator
```

---

## Quick Fix (If You're in a Hurry)

Try using `python -m pip` instead of just `pip`:

```powershell
# This bypasses the broken pip launcher
python -m pip install --upgrade protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Then install other dependencies
python -m pip install -r requirements.txt
```

---

## Complete Fresh Start Script

Save this as `setup_fresh.ps1` and run it:

```powershell
# setup_fresh.ps1
Write-Host "=== AVOS Fresh Environment Setup ===" -ForegroundColor Cyan

# Step 1: Go to parent directory
Set-Location "E:\Projects\Personal Projects\Avos Antivirus"

# Step 2: Remove old venv if exists
if (Test-Path .venv) {
    Write-Host "Removing old virtual environment..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force .venv
}

# Step 3: Create new venv
Write-Host "Creating new virtual environment..." -ForegroundColor Yellow
python -m venv .venv

# Step 4: Activate venv
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
.\.venv\Scripts\Activate.ps1

# Step 5: Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Step 6: Navigate to Avos_AiAv
Set-Location Avos_AiAv

# Step 7: Install compatible protobuf
Write-Host "Installing compatible protobuf and grpc..." -ForegroundColor Yellow
python -m pip install protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Step 8: Install all dependencies
Write-Host "Installing all dependencies..." -ForegroundColor Yellow
python -m pip install -r requirements.txt

# Step 9: Initialize database
Write-Host "Initializing database..." -ForegroundColor Yellow
python -m core.db.db_manager --init

# Step 10: Install UI dependencies
Write-Host "Installing UI dependencies..." -ForegroundColor Yellow
Set-Location ui
npm install --legacy-peer-deps
Set-Location ..

Write-Host "`n=== Setup Complete! ===" -ForegroundColor Green
Write-Host "To start AVOS:" -ForegroundColor Cyan
Write-Host "  Terminal 1: python -m core.cso.orchestrator" -ForegroundColor White
Write-Host "  Terminal 2: cd ui && npm run dev" -ForegroundColor White
```

Run it:
```powershell
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
.\setup_fresh.ps1
```

---

## Troubleshooting the Virtual Environment

### Check if venv is activated:
```powershell
# Should show (.venv) at the start of your prompt
# Example: (.venv) PS E:\Projects\...
```

### Check Python path:
```powershell
# Should point to your venv
Get-Command python | Select-Object -ExpandProperty Source

# Should show something like:
# E:\Projects\Personal Projects\Avos Antivirus\.venv\Scripts\python.exe
```

### If activation fails:
```powershell
# Enable script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then try activating again
.\.venv\Scripts\Activate.ps1
```

---

## Summary

Your issue is a **broken virtual environment path**. The fix is:

1. **Deactivate** current venv
2. **Delete** `.venv` folder
3. **Recreate** venv with `python -m venv .venv`
4. **Activate** with `.venv\Scripts\Activate.ps1`
5. **Install** dependencies with `python -m pip install ...`

**OR** just use system Python without a virtual environment.