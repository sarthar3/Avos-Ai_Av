# UI Connection Debugging Guide

## Problem: UI Shows "Cannot connect to AVOS backend"

This guide will help you diagnose and fix the connection issue between the React UI and Python backend.

---

## Step 1: Verify Backend is Running

### Check if Python backend is actually running:

```powershell
# In PowerShell, check if port 8765 is listening
netstat -ano | findstr :8765
```

**Expected output:**
```
TCP    0.0.0.0:8765           0.0.0.0:0              LISTENING       12345
TCP    [::]:8765              [::]:0                 LISTENING       12345
```

If you see this, the backend is running. If not, start it:

```powershell
cd "path\to\Avos Antivirus\Avos_AiAv"
python -m core.cso.orchestrator
```

---

## Step 2: Test Backend Directly

### Test with curl (if available):

```powershell
curl http://127.0.0.1:8765/api/status
```

### Test with PowerShell:

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8765/api/status
```

**Expected output:**
```json
{
  "version": "1.0.0",
  "mode": "normal",
  "running": true,
  "modules": [...],
  "threats_today": 0,
  "cpu_usage": 2.5,
  "ram_usage_mb": 150.2
}
```

If this works, the backend is fine. The issue is in the UI connection.

---

## Step 3: Check Browser Console

1. Open the UI in browser (http://localhost:3000)
2. Press **F12** to open Developer Tools
3. Go to **Console** tab
4. Look for error messages

### Common errors and solutions:

#### Error: "Failed to fetch" or "Network Error"
**Cause:** CORS issue or backend not running
**Solution:** 
- Verify backend is running on port 8765
- Check firewall isn't blocking port 8765

#### Error: "ERR_CONNECTION_REFUSED"
**Cause:** Backend not running or wrong port
**Solution:**
- Start backend: `python -m core.cso.orchestrator`
- Verify port 8765 is correct

#### Error: "CORS policy blocked"
**Cause:** CORS headers missing (shouldn't happen, but check)
**Solution:**
- Backend already has CORS headers in `http_server.py`
- If still blocked, try running UI with: `npm start` (not `npm run build`)

---

## Step 4: Check Network Tab

1. Open Developer Tools (F12)
2. Go to **Network** tab
3. Refresh the page
4. Look for requests to `http://127.0.0.1:8765/api/status`

### What to check:

- **Status Code:** Should be `200 OK`
- **Response:** Should contain JSON with status data
- **Timing:** Should respond within 1-2 seconds

### If request is failing:

- **Status: (failed)** → Backend not running
- **Status: 404** → Wrong URL (check port)
- **Status: 500** → Backend error (check backend logs)
- **Status: 0** → CORS or network issue

---

## Step 5: Check Backend Logs

Backend logs are in: `Avos_AiAv/logs/avos_cso.log`

Look for:
```
INFO AVOS.HTTP: AVOS HTTP REST bridge listening on http://localhost:8765
```

If you don't see this, the HTTP server didn't start.

### Common backend errors:

#### "Address already in use"
**Solution:** Kill the process using port 8765:
```powershell
# Find process using port 8765
netstat -ano | findstr :8765
# Kill it (replace PID with actual process ID)
taskkill /PID <PID> /F
```

#### "Module not found" errors
**Solution:** Reinstall dependencies:
```powershell
pip install -r requirements.txt
```

---

## Step 6: Firewall Check

Windows Firewall might be blocking port 8765.

### Allow Python through firewall:

1. Open **Windows Defender Firewall**
2. Click **Allow an app through firewall**
3. Find **Python** in the list
4. Check both **Private** and **Public** boxes
5. Click **OK**

Or run this PowerShell command as Administrator:

```powershell
New-NetFirewallRule -DisplayName "AVOS Backend" -Direction Inbound -LocalPort 8765 -Protocol TCP -Action Allow
```

---

## Step 7: Try Different Browser

Sometimes browser extensions or settings block local connections.

Try:
1. **Chrome Incognito Mode** (Ctrl+Shift+N)
2. **Edge**
3. **Firefox**

---

## Step 8: Check React Dev Server

The React dev server should be running on port 3000.

```powershell
cd "path\to\Avos Antivirus\Avos_AiAv\ui"
npm start
```

**Expected output:**
```
Compiled successfully!

You can now view avos-ui in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.x.x:3000
```

---

## Step 9: Verify Both Servers Are Running

You need **TWO** terminal windows:

### Terminal 1 - Backend:
```powershell
cd "path\to\Avos Antivirus\Avos_AiAv"
python -m core.cso.orchestrator
```
**Should show:** `AVOS HTTP REST bridge listening on http://localhost:8765`

### Terminal 2 - Frontend:
```powershell
cd "path\to\Avos Antivirus\Avos_AiAv\ui"
npm start
```
**Should show:** `Compiled successfully!`

---

## Step 10: Manual Connection Test

Open browser console (F12) and run:

```javascript
fetch('http://127.0.0.1:8765/api/status')
  .then(r => r.json())
  .then(data => console.log('✅ Backend connected:', data))
  .catch(err => console.error('❌ Backend error:', err));
```

If this works, the backend is fine and the issue is in the React code.

---

## Step 11: Check for Port Conflicts

Make sure nothing else is using port 8765:

```powershell
netstat -ano | findstr :8765
```

If another process is using it, either:
1. Kill that process
2. Change the port in both:
   - `Avos_AiAv/core/api/http_server.py` (line 22: `PORT = 8765`)
   - `Avos_AiAv/ui/src/api.ts` (line 7: `const HTTP_BASE = 'http://127.0.0.1:8765'`)

---

## Step 12: Fresh Start

If nothing works, try a complete restart:

```powershell
# 1. Kill all Python and Node processes
taskkill /F /IM python.exe
taskkill /F /IM node.exe

# 2. Clear npm cache
cd "path\to\Avos Antivirus\Avos_AiAv\ui"
npm cache clean --force
rm -rf node_modules
npm install --legacy-peer-deps

# 3. Start backend
cd ..
python -m core.cso.orchestrator

# 4. In new terminal, start frontend
cd ui
npm start
```

---

## Quick Checklist

- [ ] Backend running on port 8765
- [ ] Frontend running on port 3000
- [ ] Port 8765 not blocked by firewall
- [ ] No CORS errors in browser console
- [ ] Backend responds to `curl http://127.0.0.1:8765/api/status`
- [ ] Both terminals show no errors
- [ ] Browser console shows connection logs

---

## Still Not Working?

### Collect this information:

1. **Backend logs:** `Avos_AiAv/logs/avos_cso.log` (last 50 lines)
2. **Browser console errors:** Screenshot of F12 Console tab
3. **Network tab:** Screenshot of failed requests
4. **Port check:** Output of `netstat -ano | findstr :8765`
5. **Python version:** `python --version`
6. **Node version:** `node --version`

### Common Solutions:

| Symptom | Solution |
|---------|----------|
| "Cannot connect" after 12 seconds | Backend not running or port blocked |
| Immediate "Cannot connect" | Wrong URL or port |
| Works in curl, not in browser | CORS issue (shouldn't happen) |
| Backend crashes on start | Missing dependencies or database issue |
| UI loads but shows old data | Browser cache - hard refresh (Ctrl+Shift+R) |

---

## Success Indicators

When everything works correctly, you should see:

### Backend Terminal:
```
INFO AVOS.CSO: Starting AVOS Central Security Orchestrator v1.0.0
INFO AVOS.HTTP: AVOS HTTP REST bridge listening on http://localhost:8765
INFO AVOS.GRPC: gRPC server listening on localhost:50051
```

### Frontend Terminal:
```
Compiled successfully!
webpack compiled successfully
```

### Browser Console:
```
✅ Successfully connected to AVOS backend: {version: "1.0.0", mode: "normal", ...}
```

### UI:
- Dashboard loads with system stats
- No error messages
- Real-time updates every 2.5 seconds