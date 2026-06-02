const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // ─── Window Controls ────────────────────────────────────────────────────
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close:    () => ipcRenderer.send('window-close'),

  // ─── Real-Time Event Streams ─────────────────────────────────────────────
  onThreatDetected: (callback) =>
    ipcRenderer.on('threat-detected', (event, value) => callback(value)),
  onStatusUpdate: (callback) =>
    ipcRenderer.on('status-update', (event, value) => callback(value)),

  // ─── Mode & Module Config ────────────────────────────────────────────────
  setMode:         (mode)            => ipcRenderer.invoke('set-mode', mode),
  setModuleConfig: (name, enabled)   => ipcRenderer.invoke('set-module-config', { name, enabled }),

  // ─── Threats ─────────────────────────────────────────────────────────────
  getThreats:    (limit, offset, filter) =>
    ipcRenderer.invoke('get-threats', { limit, offset, filter }),
  quarantineFile: (filePath) => ipcRenderer.invoke('quarantine-file', filePath),

  // ─── On-Demand Scan ──────────────────────────────────────────────────────
  scanFile: (filePath) => ipcRenderer.invoke('scan-file', filePath),

  // ─── AI Chat ─────────────────────────────────────────────────────────────
  chat: (question, eventId) => ipcRenderer.invoke('chat', { question, eventId }),

  // ─── Dark Web Breach Alerts ───────────────────────────────────────────────
  getBreachAlerts: () => ipcRenderer.invoke('get-breach-alerts'),

  // ─── Payment Shield ───────────────────────────────────────────────────────
  launchSecureBrowser: (url) => ipcRenderer.invoke('launch-secure-browser', url),
  tokenizeCardData:    (card, exp, cvv) =>
    ipcRenderer.invoke('tokenize-card-data', { card, exp, cvv }),
  wipeClipboard: () => ipcRenderer.invoke('wipe-clipboard'),

  // ─── DNS Audit ───────────────────────────────────────────────────────────
  auditDns: (domains) => ipcRenderer.invoke('audit-dns', domains),

  // ─── Utilities ───────────────────────────────────────────────────────────
  scanRegistry: ()                        => ipcRenderer.invoke('scan-registry'),
  cleanTemp:    (includeBrowserCache)     => ipcRenderer.invoke('clean-temp', includeBrowserCache),
  lockFolder:   (folderPath, password)    => ipcRenderer.invoke('lock-folder', { folderPath, password }),
  unlockFolder: (folderPath, password)    => ipcRenderer.invoke('unlock-folder', { folderPath, password }),

  // ─── Firewall Rules ──────────────────────────────────────────────────────
  getFirewallRules: () => ipcRenderer.invoke('get-firewall-rules'),

  // ─── EDR Events ──────────────────────────────────────────────────────────
  getEDREvents: (limit) => ipcRenderer.invoke('get-edr-events', limit),
});
