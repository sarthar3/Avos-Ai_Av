# 🔧 AVOS Troubleshooting Guide

## Common Issues and Solutions

---

## Issue 1: "Cannot find path 'ui'" ❌

### Error
```
cd : Cannot find path 'E:\Projects\Personal Projects\Avos Antivirus\ui' because it does not exist.
```

### Solution
You're in the wrong directory! The project structure is:
```
Avos Antivirus/          ← You are here (WRONG)
└── Avos_AiAv/           ← You need to be here
    ├── ui/              ← UI is inside Avos_AiAv
    ├── core/
    └── ...
```

**Fix:**
```bash
# Navigate to the correct directory
cd "Avos_AiAv"

# Now you can access ui/
cd ui
npm run dev
```

---

## Issue 2: Protobuf ImportError ❌

### Error
```
ImportError: cannot import name 'runtime_version' from 'google.protobuf'
```

### Root Cause
The generated protobuf files (`avos_pb2.py`) were created with a newer version of protobuf than what's installed in your virtual environment.

### Solution A: Upgrade Protobuf (Recommended)
```bash
# Activate virtual environment
.venv\Scripts\activate

# Upgrade protobuf to latest version
pip install --upgrade protobuf grpcio grpcio-tools

# Verify installation
python -c "import google.protobuf; print(google.protobuf.__version__)"
```

### Solution B: Regenerate Protobuf Files
```bash
cd Avos_AiAv

# Regenerate Python files from .proto
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. shared/proto/avos.proto
```

### Solution C: Downgrade Protobuf (Not Recommended)
```bash
pip install protobuf==4.25.3
```

---

## Issue 3: Module Import Errors

### Error
```
ModuleNotFoundError: No module named 'core'
```

### Solution
Make sure you're running from the `Avos_AiAv` directory:
```bash
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
python -m core.cso.orchestrator
```

---

## Complete Fresh Start Guide

If you're having multiple issues, follow this complete reset:

### Step 1: Navigate to Correct Directory
```powershell
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
```

### Step 2: Fix Python Dependencies
```powershell
# Activate virtual environment
..\.venv\Scripts\activate

# Upgrade protobuf and grpc
pip install --upgrade protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Verify
python -c "from google.protobuf import runtime_version; print('Protobuf OK')"
```

### Step 3: Regenerate Protobuf Files (if needed)
```powershell
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. shared/proto/avos.proto
```

### Step 4: Initialize Database
```powershell
python -m core.db.db_manager --init
```

### Step 5: Start Backend
```powershell
python -m core.cso.orchestrator
```

### Step 6: Start UI (New Terminal)
```powershell
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv\ui"
npm run dev
```

---

## Quick Reference: Correct Paths

### Backend Commands (from Avos_AiAv/)
```powershell
# You should be here:
E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv\

# Run backend:
python -m core.cso.orchestrator

# Run tests:
python -m pytest tests/ -v

# Initialize DB:
python -m core.db.db_manager --init
```

### UI Commands (from Avos_AiAv/ui/)
```powershell
# You should be here:
E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv\ui\

# Install dependencies:
npm install --legacy-peer-deps

# Run dev server:
npm run dev

# Run Electron:
npm run electron
```

---

## Automated Launcher Fix

The `run_avos.ps1` script should be run from the `Avos_AiAv` directory:

```powershell
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
.\run_avos.ps1
```

---

## Verification Commands

### Check if you're in the right directory:
```powershell
# Should show: Avos_AiAv
Split-Path -Leaf (Get-Location)

# Should list: core, ui, shared, logs, etc.
Get-ChildItem -Name
```

### Check Python environment:
```powershell
# Should show Python 3.11+
python --version

# Should show your venv path
Get-Command python | Select-Object -ExpandProperty Source
```

### Check Node environment:
```powershell
# Should show Node 18+
node --version

# Should show npm 9+
npm --version
```

---

## Port Conflicts

If ports are already in use:

### Check what's using the ports:
```powershell
# Check gRPC port
netstat -ano | findstr :50051

# Check HTTP port
netstat -ano | findstr :8765

# Check React dev port
netstat -ano | findstr :3000
```

### Kill process using port:
```powershell
# Replace <PID> with the process ID from netstat
Stop-Process -Id <PID> -Force
```

---

## Still Having Issues?

### Collect Debug Information:
```powershell
# Python version
python --version

# Installed packages
pip list | findstr -i "grpc proto"

# Current directory
Get-Location

# Directory contents
Get-ChildItem -Name

# Environment variables
$env:PYTHONPATH
```

### Check Logs:
```powershell
# View backend logs
Get-Content logs\avos_cso.log -Tail 50

# View with live updates
Get-Content logs\avos_cso.log -Wait -Tail 50
```

---

## Summary of Common Mistakes

1. ❌ Running from wrong directory (parent instead of Avos_AiAv)
2. ❌ Outdated protobuf version
3. ❌ Virtual environment not activated
4. ❌ Missing npm dependencies
5. ❌ Port conflicts with other applications

**Always ensure you're in the `Avos_AiAv` directory before running any commands!**