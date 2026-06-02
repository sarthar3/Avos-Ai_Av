/**
 * AVOS Unified API Client
 * Automatically uses window.electronAPI (Electron IPC) when available,
 * or falls back to HTTP fetch calls to localhost:8765 (browser mode).
 */

const HTTP_BASE = 'http://127.0.0.1:8765';
const isElectron = () => typeof window !== 'undefined' && !!window.electronAPI;

async function httpGet<T>(path: string): Promise<T> {
  try {
    const res = await fetch(`${HTTP_BASE}${path}`, {
      mode: 'cors',
      credentials: 'omit',
    });
    if (!res.ok) {
      console.error(`HTTP GET ${path} failed: ${res.status} ${res.statusText}`);
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json();
  } catch (error) {
    console.error(`HTTP GET ${path} error:`, error);
    throw error;
  }
}

async function httpPost<T>(path: string, body: any = {}): Promise<T> {
  try {
    const res = await fetch(`${HTTP_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      mode: 'cors',
      credentials: 'omit',
    });
    if (!res.ok) {
      console.error(`HTTP POST ${path} failed: ${res.status} ${res.statusText}`);
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json();
  } catch (error) {
    console.error(`HTTP POST ${path} error:`, error);
    throw error;
  }
}

// ─── Status & Polling ─────────────────────────────────────────────────────────

/** Get current system status (CPU, RAM, modules, mode, threats_today). */
export async function getStatus(): Promise<any> {
  return httpGet('/api/status');
}

// ─── Threats ──────────────────────────────────────────────────────────────────

export async function getThreats(limit = 100, offset = 0, filter = ''): Promise<any> {
  if (isElectron()) return window.electronAPI!.getThreats(limit, offset, filter);
  return httpGet(`/api/threats?limit=${limit}&offset=${offset}&filter=${filter}`);
}

export async function quarantineFile(path: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.quarantineFile(path);
  return httpPost('/api/quarantine', { path });
}

export async function scanFile(path: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.scanFile(path);
  return httpPost('/api/scan-file', { path });
}

// ─── Mode & Modules ───────────────────────────────────────────────────────────

export async function setMode(mode: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.setMode(mode);
  return httpPost('/api/mode', { mode });
}

export async function setModuleConfig(name: string, enabled: boolean): Promise<any> {
  if (isElectron()) return window.electronAPI!.setModuleConfig(name, enabled);
  return httpPost('/api/module-config', { name, enabled });
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

export async function chat(question: string, eventId?: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.chat(question, eventId);
  return httpPost('/api/chat', { question, event_id: eventId || '' });
}

// ─── Payment Shield ───────────────────────────────────────────────────────────

export async function tokenizeCardData(card: string, exp: string, cvv: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.tokenizeCardData(card, exp, cvv);
  return httpPost('/api/tokenize', { card, exp, cvv });
}

export async function wipeClipboard(): Promise<any> {
  if (isElectron()) return window.electronAPI!.wipeClipboard();
  return httpPost('/api/wipe-clipboard');
}

export async function launchSecureBrowser(url: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.launchSecureBrowser(url);
  return httpPost('/api/launch-browser', { url });
}

// ─── DNS Audit ────────────────────────────────────────────────────────────────

export async function auditDns(domains: string[]): Promise<any> {
  if (isElectron()) return window.electronAPI!.auditDns(domains);
  return httpPost('/api/audit-dns', { domains });
}

// ─── Utilities ────────────────────────────────────────────────────────────────

export async function scanRegistry(): Promise<any> {
  if (isElectron()) return window.electronAPI!.scanRegistry();
  return httpPost('/api/scan-registry');
}

export async function cleanTemp(includeBrowserCache = true): Promise<any> {
  if (isElectron()) return window.electronAPI!.cleanTemp(includeBrowserCache);
  return httpPost('/api/clean-temp', { include_browser_cache: includeBrowserCache });
}

export async function lockFolder(path: string, password: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.lockFolder(path, password);
  return httpPost('/api/lock-folder', { path, password });
}

export async function unlockFolder(path: string, password: string): Promise<any> {
  if (isElectron()) return window.electronAPI!.unlockFolder(path, password);
  return httpPost('/api/unlock-folder', { path, password });
}

// ─── Firewall ─────────────────────────────────────────────────────────────────

export async function getFirewallRules(): Promise<any> {
  if (isElectron()) return window.electronAPI!.getFirewallRules();
  return httpGet('/api/firewall-rules');
}

// ─── EDR Events ──────────────────────────────────────────────────────────────

export async function getEDREvents(limit = 200): Promise<any> {
  if (isElectron()) return window.electronAPI!.getEDREvents(limit);
  return httpGet(`/api/edr-events?limit=${limit}`);
}

// ─── Breach Alerts ────────────────────────────────────────────────────────────

export async function getBreachAlerts(): Promise<any> {
  if (isElectron()) return window.electronAPI!.getBreachAlerts();
  return httpGet('/api/breach-alerts');
}

// ─── Status subscription ─────────────────────────────────────────────────────
// In Electron: uses real-time IPC events pushed from main.js
// In browser:  uses polling every 2.5 seconds via HTTP

export function subscribeStatus(callback: (status: any) => void): () => void {
  if (isElectron()) {
    window.electronAPI!.onStatusUpdate(callback);
    return () => {}; // Electron listeners can't be removed (event driven)
  }

  // Browser polling mode
  let active = true;
  let firstAttempt = true;
  const poll = async () => {
    while (active) {
      try {
        const status = await getStatus();
        if (firstAttempt) {
          console.log('✅ Successfully connected to AVOS backend:', status);
          firstAttempt = false;
        }
        callback(status);
      } catch (error) {
        if (firstAttempt) {
          console.error('❌ Failed to connect to AVOS backend:', error);
        }
        // Backend not yet up — keep trying silently
      }
      await new Promise(r => setTimeout(r, 2500));
    }
  };
  poll();
  return () => { active = false; };
}

export function subscribeThreatStream(callback: (threat: any) => void): () => void {
  if (isElectron()) {
    window.electronAPI!.onThreatDetected(callback);
    return () => {};
  }

  // Browser polling mode — poll /api/threats every 5s and emit new ones
  let active = true;
  let lastSeen = new Set<string>();

  const poll = async () => {
    while (active) {
      try {
        const res = await getThreats(20, 0, '');
        const threats: any[] = res?.threats || [];
        for (const t of threats) {
          if (!lastSeen.has(t.event_id)) {
            lastSeen.add(t.event_id);
            callback(t);
          }
        }
      } catch {
        // Silently ignore
      }
      await new Promise(r => setTimeout(r, 5000));
    }
  };
  poll();
  return () => { active = false; };
}
