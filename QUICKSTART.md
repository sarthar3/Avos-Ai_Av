# 🚀 AVOS Quick Start Guide

Complete setup and run instructions for the AVOS AI-powered security platform.

---

## 📋 Prerequisites

### Required Software
- **Python 3.11+** - [Download](https://www.python.org/downloads/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **Git** - [Download](https://git-scm.com/)

### Optional (for advanced features)
- **Rust & Cargo** - For PE parser compilation
- **Windows Driver Kit (WDK)** - For kernel driver development
- **Visual Studio 2022** - For C++ driver compilation

---

## ⚡ Quick Start (5 Minutes)

### Step 0: Navigate to Project Directory
```bash
# IMPORTANT: Make sure you're in the Avos_AiAv directory!
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"

# Verify you're in the right place (should show: Avos_AiAv)
Split-Path -Leaf (Get-Location)
```

### Step 1: Fix Protobuf Dependencies
```bash
# Activate virtual environment (if using one)
..\.venv\Scripts\activate

# Upgrade protobuf and grpc to compatible versions
pip install --upgrade protobuf==5.26.1 grpcio==1.62.1 grpcio-tools==1.62.1

# Install other dependencies
pip install -r requirements.txt
```

### Step 2: Initialize Database
```bash
python -m core.db.db_manager --init
```

### Step 3: Install UI Dependencies
```bash
cd ui
npm install --legacy-peer-deps
cd ..
```

### Step 4: Run AVOS

**IMPORTANT**: All commands must be run from the `Avos_AiAv` directory!

```powershell
# Option A: Use the automated launcher (Recommended)
# Make sure you're in Avos_AiAv directory first!
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
.\run_avos.ps1

# Option B: Manual start
# Terminal 1 - Start backend (from Avos_AiAv directory)
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv"
python -m core.cso.orchestrator

# Terminal 2 - Start UI (from Avos_AiAv/ui directory)
cd "E:\Projects\Personal Projects\Avos Antivirus\Avos_AiAv\ui"
npm run dev
```

The AVOS dashboard will open automatically in Electron. Backend runs on:
- **gRPC**: `localhost:50051`
- **HTTP REST**: `localhost:8765`

---

## 🎯 Running Modes

### Mode 1: Native Desktop App (Electron)
**Best for**: Full system integration with IPC
```bash
cd ui
npm run dev
```
- Opens native window
- Full Windows API access
- Real-time threat streaming via gRPC

### Mode 2: Web Browser Mode
**Best for**: Development and testing
```bash
cd ui
npm run start
```
- Opens at `http://localhost:3000`
- Uses HTTP REST API polling
- No Electron overhead

### Mode 3: Production Build
```bash
cd ui
npm run build
npm run electron
```

---

## 🧪 Testing

### Run Full Test Suite
```bash
# All tests
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_avos.py -v

# With coverage
python -m pytest tests/ --cov=core --cov-report=html
```

### Test Individual Modules
```bash
# Test signature scanner
python -m pytest tests/test_avos.py::TestSignatureEngine -v

# Test WAF
python -m pytest tests/test_avos.py::TestWAF -v

# Test payment shield
python -m pytest tests/test_payment_shield.py -v
```

---

## 🔧 Configuration

### Edit Settings
```bash
# Main config file
notepad Avos_AiAv/shared/config/avos_config.yaml
```

### Key Configuration Options

```yaml
# Enable/disable modules
modules:
  signature_scan: true
  ai_predictor: true
  payment_shield: true
  sandbox: false        # Enable manually

# Performance tuning
performance:
  max_concurrent_scans: 4
  idle_cpu_target_pct: 1.0
  max_ram_mb: 50

# Security thresholds
thresholds:
  heuristic_alert: 60.0
  ai_alert: 70.0
  ransomware_files_per_10s: 50
```

---

## 🛠️ Advanced Setup

### Build Rust Parsers (Optional)
```bash
cd parsers
cargo build --release
# Output: target/release/avos_parsers.pyd
```

### Compile Kernel Drivers (Development Only)
⚠️ **Requires WDK and test signing mode**

```bash
# Enable test signing (Admin PowerShell)
bcdedit /set testsigning on
# Restart required

# Build minifilter driver
cd drivers/minifilter
cmake -B build
cmake --build build --config Release
```

---

## 📊 Monitoring & Logs

### View Logs
```bash
# Real-time log monitoring
Get-Content logs/avos_cso.log -Wait -Tail 50

# Or use any text editor
notepad logs/avos_cso.log
```

### Database Inspection
```bash
# SQLite CLI
sqlite3 logs/avos.db

# View threats
sqlite3 logs/avos.db "SELECT * FROM threats ORDER BY timestamp DESC LIMIT 10;"
```

---

## 🎮 Operation Modes

### Normal Mode (Default)
Full protection with all modules active
```python
# Via UI: Settings → Mode → Normal
# Via API: POST /api/mode {"mode": "normal"}
```

### Gamer Mode
Minimal scanning during gaming sessions
```python
# Disables file write/create events
# Reduces CPU usage to <0.5%
```

### Developer Mode
Verbose logging and whitelisting
```python
# Detailed logs for debugging
# Custom whitelist support
```

---

## 🔐 Security Features

### Payment Shield
- Clipboard monitoring for card data
- DNS poisoning detection
- Secure browser isolation
- Card tokenization (AES-256)

### Ransomware Protection
- Mass encryption detection
- Automatic process termination
- File backup on suspicious activity

### AI Threat Detection
- Random Forest classifier (static analysis)
- LSTM behavioral analysis
- Offline-capable (no cloud required)

---

## 🐛 Troubleshooting

### Backend Won't Start
```bash
# Check Python version
python --version  # Should be 3.11+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check port availability
netstat -ano | findstr :50051
netstat -ano | findstr :8765
```

### UI Won't Load
```bash
# Clear node modules and reinstall
cd ui
rm -rf node_modules package-lock.json
npm install --legacy-peer-deps

# Check Node version
node --version  # Should be 18+
```

### Database Errors
```bash
# Reinitialize database
rm logs/avos.db
python -m core.db.db_manager --init
```

### YARA Not Working
```bash
# Install yara-python
pip install yara-python

# Verify installation
python -c "import yara; print('YARA OK')"
```

---

## 📚 Additional Resources

- **Main README**: `README.md` - Architecture and features
- **API Documentation**: Check `core/api/http_server.py` for endpoints
- **Test Examples**: `tests/test_avos.py` - Usage examples
- **Configuration**: `shared/config/avos_config.yaml` - All settings

---

## 🆘 Getting Help

### Common Commands
```bash
# Check system status
curl http://localhost:8765/api/status

# Scan a file
curl -X POST http://localhost:8765/api/scan -d '{"path":"C:\\test.exe"}'

# Get recent threats
curl http://localhost:8765/api/threats?limit=10
```

### Log Locations
- **Backend logs**: `logs/avos_cso.log`
- **Database**: `logs/avos.db`
- **Quarantine**: `quarantine/`
- **Models**: `models/`

---

## ✅ Verification Checklist

After setup, verify:
- [ ] Backend starts without errors
- [ ] UI loads and shows dashboard
- [ ] Database initialized (`logs/avos.db` exists)
- [ ] Test suite passes (`pytest tests/ -v`)
- [ ] Can scan a test file
- [ ] Threats appear in UI
- [ ] Logs are being written

---

## 🚀 Next Steps

1. **Configure modules** in `avos_config.yaml`
2. **Run test scan** on a safe file
3. **Monitor dashboard** for real-time threats
4. **Review logs** to understand system behavior
5. **Customize rules** in `signatures/custom_rules.yar`

---

**Need more help?** Check the main `README.md` or review the test files for usage examples.