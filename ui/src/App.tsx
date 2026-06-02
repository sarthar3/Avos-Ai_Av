import React, { useState, useEffect, useRef, useCallback } from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Activity, Wifi, Brain, Settings, AlertTriangle,
  Database, Lock, Zap, Eye, Cpu, HardDrive, Moon, Code,
  CreditCard, RefreshCw, ChevronRight, Search, Trash2
} from 'lucide-react';
import './index.css';

import * as api from './api';

// ─── TypeScript Globals ──────────────────────────────────────────────────────
declare global {
  interface Window {
    electronAPI?: {
      minimize:         () => void;
      maximize:         () => void;
      close:            () => void;
      onThreatDetected: (cb: (t: any) => void) => void;
      onStatusUpdate:   (cb: (s: any) => void) => void;
      setMode:          (mode: string) => Promise<any>;
      setModuleConfig:  (name: string, enabled: boolean) => Promise<any>;
      getThreats:       (limit: number, offset: number, filter: string) => Promise<any>;
      quarantineFile:   (path: string) => Promise<any>;
      scanFile:         (path: string) => Promise<any>;
      chat:             (question: string, eventId?: string) => Promise<any>;
      getBreachAlerts:  () => Promise<any>;
      launchSecureBrowser: (url: string) => Promise<any>;
      tokenizeCardData: (card: string, exp: string, cvv: string) => Promise<any>;
      wipeClipboard:    () => Promise<any>;
      auditDns:         (domains: string[]) => Promise<any>;
      scanRegistry:     () => Promise<any>;
      cleanTemp:        (includeBrowserCache: boolean) => Promise<any>;
      lockFolder:       (path: string, password: string) => Promise<any>;
      unlockFolder:     (path: string, password: string) => Promise<any>;
      getFirewallRules: () => Promise<any>;
      getEDREvents:     (limit: number) => Promise<any>;
    };
  }
}

// ─── Types ────────────────────────────────────────────────────────────────────
interface ThreatEvent {
  event_id:     string;
  event_type:   string;
  threat_level: string;
  score:        number;
  source:       string;
  path?:        string;
  pid?:         number;
  explanation:  string;
  timestamp:    number;
  remediated:   boolean;
}

interface SystemStatus {
  mode:          string;
  running:       boolean;
  threats_today: number;
  cpu_usage:     number;
  ram_usage_mb:  number;
  modules:       Record<string, { name: string; enabled: boolean; healthy: boolean }>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function timeAgo(ts: number): string {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function levelClass(level: string) { return `badge badge-${level.toLowerCase()}`; }

/** Normalize status: modules may be an array (gRPC) or object (HTTP) */
function normalizeStatus(raw: any): SystemStatus {
  const modulesObj: Record<string, any> = {};
  if (Array.isArray(raw.modules)) {
    raw.modules.forEach((m: any) => { modulesObj[m.name] = m; });
  } else {
    Object.assign(modulesObj, raw.modules || {});
  }
  return { ...raw, modules: modulesObj };
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
const NAV = [
  { to: '/',          icon: Activity,      label: 'Dashboard'      },
  { to: '/threats',   icon: AlertTriangle, label: 'Threats'        },
  { to: '/firewall',  icon: Wifi,          label: 'Firewall'       },
  { to: '/payment',   icon: CreditCard,    label: 'Payment Shield' },
  { to: '/ai-chat',   icon: Brain,         label: 'AI Assistant'   },
  { to: '/edr',       icon: Eye,           label: 'EDR'            },
  { to: '/utilities', icon: Database,      label: 'Utilities'      },
  { to: '/settings',  icon: Settings,      label: 'Settings'       },
];

function Sidebar({ mode, onModeChange }: { mode: string; onModeChange: (m: string) => void }) {
  return (
    <aside style={{
      width: 240, minHeight: '100vh', background: 'rgba(244,245,246,0.97)',
      borderRight: '1px solid rgba(0,0,0,0.05)',
      display: 'flex', flexDirection: 'column', padding: '24px 0', zIndex: 10,
    }}>
      <div style={{ padding: '0 24px 24px', borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            border: '2px solid #111827', display: 'grid',
            gridTemplateColumns: '1fr 1fr', gridTemplateRows: '1fr 1fr',
            overflow: 'hidden', background: '#111827', gap: '1.5px',
            boxShadow: '0 4px 10px rgba(0,0,0,0.06)', flexShrink: 0,
          }}>
            <div style={{ background: 'linear-gradient(135deg,#f8fafc,#cbd5e1)' }} />
            <div style={{ background: 'linear-gradient(225deg,#cbd5e1,#94a3b8)' }} />
            <div style={{ background: 'linear-gradient(45deg,#cbd5e1,#94a3b8)' }} />
            <div style={{ background: 'linear-gradient(315deg,#f8fafc,#cbd5e1)' }} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.3px', color: '#111827' }}>AVOS</div>
            <div style={{ fontSize: 9, color: '#4f46e5', fontWeight: 700, letterSpacing: '0.5px' }}>SECURITY</div>
          </div>
        </div>
      </div>

      <div style={{ padding: '16px 24px', borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="animate-pulse-dot dot-green" />
          <span style={{ fontSize: 12, color: '#10b981', fontWeight: 600 }}>PROTECTED</span>
        </div>
      </div>

      <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'} style={{ textDecoration: 'none' }}>
            {({ isActive }) => (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 14px', borderRadius: 14,
                background: isActive ? '#ffffff' : 'transparent',
                boxShadow: isActive ? '0 4px 12px rgba(0,0,0,0.03)' : 'none',
                color: isActive ? '#111827' : '#64748b',
                fontWeight: isActive ? 600 : 500, fontSize: 13,
                transition: 'all 0.25s cubic-bezier(0.4,0,0.2,1)', cursor: 'pointer',
              }}>
                <Icon size={18} strokeWidth={isActive ? 2.2 : 1.8} color={isActive ? '#111827' : '#64748b'} />
                {label}
              </div>
            )}
          </NavLink>
        ))}
      </nav>

      <div style={{ padding: '20px 24px', borderTop: '1px solid rgba(0,0,0,0.05)' }}>
        <div style={{ fontSize: 11, color: '#64748b', marginBottom: 10, fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: 0.8 }}>Mode</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {['normal', 'gamer', 'developer'].map(m => (
            <button key={m} onClick={() => onModeChange(m)} style={{
              display: 'flex', alignItems: 'center', gap: 8, width: '100%',
              padding: '8px 12px', background: 'none', border: 'none', cursor: 'pointer',
              color: mode === m ? '#111827' : '#64748b', borderRadius: 8,
              fontSize: 12, fontWeight: mode === m ? 600 : 400,
              fontFamily: 'Inter, sans-serif', textAlign: 'left', transition: 'all 0.2s',
            }}>
              {m === 'gamer' ? <Moon size={13} /> : m === 'developer' ? <Code size={13} /> : <Zap size={13} />}
              {m.charAt(0).toUpperCase() + m.slice(1)}
              {mode === m && <ChevronRight size={12} style={{ marginLeft: 'auto' }} />}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function Dashboard({ status, threats }: { status: SystemStatus; threats: ThreatEvent[] }) {
  const recent = [...threats].sort((a, b) => b.timestamp - a.timestamp).slice(0, 5);
  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 24 }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Security Dashboard</h1>
      <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24 }}>Real-time threat monitoring and system health</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Threats Today', value: status.threats_today, color: status.threats_today > 0 ? 'danger' : 'safe', icon: AlertTriangle },
          { label: 'CPU Usage',     value: `${status.cpu_usage.toFixed(1)}%`, color: status.cpu_usage > 80 ? 'danger' : 'safe', icon: Cpu },
          { label: 'RAM Usage',     value: `${status.ram_usage_mb.toFixed(1)} MB`, color: '', icon: HardDrive },
          { label: 'Active Modules',value: Object.values(status.modules).filter(m => m.enabled).length, color: 'safe', icon: Shield },
        ].map(({ label, value, color, icon: Icon }, i) => (
          <motion.div className="card" key={label}
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 8 }}>{label}</div>
                <div className={`stat-value ${color}`}>{value}</div>
              </div>
              <Icon size={20} color="#3b82f6" style={{ opacity: 0.6 }} />
            </div>
          </motion.div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>🛡️ Module Status</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {Object.values(status.modules).map(mod => (
              <div key={mod.name} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 10px', borderRadius: 8, background: '#f8fafc',
                border: '1px solid rgba(0,0,0,0.05)',
              }}>
                <span className={`animate-pulse-dot ${mod.enabled && mod.healthy ? 'dot-green' : 'dot-red'}`} />
                <span style={{ fontSize: 11, color: '#4b5563', overflow: 'hidden',
                  textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mod.name}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>⚡ Recent Threats</h3>
          {recent.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#64748b', padding: '20px 0' }}>
              <Shield size={32} color="#10b981" /><br />No threats detected
            </div>
          ) : recent.map(t => (
            <div key={t.event_id} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 0', borderBottom: '1px solid rgba(0,0,0,0.05)'
            }}>
              <span className={levelClass(t.threat_level)}>{t.threat_level}</span>
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#111827',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.event_type.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: 11, color: '#64748b' }}>{timeAgo(t.timestamp)}</div>
              </div>
              {t.remediated && <span style={{ fontSize: 10, color: '#10b981', fontWeight: 600 }}>✓</span>}
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ─── Threats Page ─────────────────────────────────────────────────────────────
function ThreatsPage({ threats, onQuarantine }: { threats: ThreatEvent[]; onQuarantine: (path: string) => void }) {
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [filter, setFilter]     = useState('');
  const [quarantining, setQ]    = useState<string | null>(null);

  const sorted = [...threats]
    .filter(t => !filter || t.threat_level === filter.toUpperCase())
    .sort((a, b) => b.timestamp - a.timestamp);

  const doQuarantine = async (path: string) => {
    setQ(path);
    try { await api.quarantineFile(path); onQuarantine(path); }
    catch (e) { console.error(e); }
    finally { setQ(null); }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Threat Log</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`btn ${filter === f ? 'btn-primary' : 'btn-ghost'}`}
              style={{ padding: '5px 12px', fontSize: 11 }}>{f || 'All'}</button>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, flex: 1, overflow: 'hidden' }}>
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {sorted.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: 40 }}>
              <Shield size={40} color="#10b981" style={{ marginBottom: 12 }} />
              <div style={{ color: '#64748b', fontSize: 14 }}>No threats detected — system is clean</div>
            </div>
          ) : sorted.map(t => (
            <motion.div key={t.event_id}
              className={`card ${t.threat_level === 'CRITICAL' ? 'card-danger' : ''}`}
              style={{ cursor: 'pointer', padding: '14px 16px', flexShrink: 0 }}
              onClick={() => setSelected(t)} whileHover={{ scale: 1.005 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={levelClass(t.threat_level)}>{t.threat_level}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: '#111827' }}>
                    {t.event_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  </div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>{t.source} · {timeAgo(t.timestamp)}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: t.score >= 80 ? '#ef4444' : '#f97316' }}>
                    {t.score.toFixed(0)}
                  </div>
                  <div style={{ fontSize: 10, color: '#64748b' }}>score</div>
                </div>
              </div>
              {t.path && <div className="mono" style={{ marginTop: 6, fontSize: 11 }}>{t.path}</div>}
            </motion.div>
          ))}
        </div>

        <AnimatePresence>
          {selected && (
            <motion.div className="card" initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }}
              exit={{ x: 40, opacity: 0 }} style={{ width: 320, flexShrink: 0, overflow: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h3 style={{ fontSize: 15, fontWeight: 700 }}>Threat Detail</h3>
                <button onClick={() => setSelected(null)}
                  style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 20 }}>×</button>
              </div>
              <span className={levelClass(selected.threat_level)}
                style={{ marginBottom: 16, display: 'inline-block' }}>{selected.threat_level}</span>
              <div className="sep" />
              {[
                ['Type',   selected.event_type.replace(/_/g, ' ')],
                ['Source', selected.source],
                ['Score',  `${selected.score.toFixed(1)}/100`],
                ['PID',    selected.pid || 'N/A'],
                ['Time',   new Date(selected.timestamp * 1000).toLocaleString()],
                ['Status', selected.remediated ? '✅ Remediated' : '⚠️ Pending'],
              ].map(([k, v]) => (
                <div key={String(k)} style={{ display: 'flex', justifyContent: 'space-between',
                  padding: '6px 0', borderBottom: '1px solid rgba(0,0,0,0.05)', fontSize: 12 }}>
                  <span style={{ color: '#64748b' }}>{k}</span>
                  <span style={{ color: '#111827', fontWeight: 600 }}>{v}</span>
                </div>
              ))}
              {selected.path && (
                <>
                  <div className="sep" />
                  <div style={{ fontSize: 11, color: '#64748b' }}>File Path</div>
                  <div className="mono" style={{ marginTop: 4, wordBreak: 'break-all' }}>{selected.path}</div>
                  {!selected.remediated && (
                    <button className="btn btn-danger" style={{ width: '100%', marginTop: 12 }}
                      onClick={() => doQuarantine(selected.path!)}
                      disabled={quarantining === selected.path}>
                      {quarantining === selected.path
                        ? <RefreshCw size={14} className="animate-spin" />
                        : <><Trash2 size={14} />Quarantine File</>}
                    </button>
                  )}
                </>
              )}
              <div className="sep" />
              <div style={{ fontSize: 11, color: '#64748b', marginBottom: 6 }}>💡 AI Explanation</div>
              <div style={{ fontSize: 12, color: '#4b5563', lineHeight: 1.6, background: '#f8fafc',
                padding: 12, borderRadius: 8, border: '1px solid rgba(0,0,0,0.05)' }}>
                {selected.explanation}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

// ─── Payment Shield ───────────────────────────────────────────────────────────
function PaymentShieldPage() {
  const [card, setCard]     = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvv, setCvv]       = useState('');
  const [token, setToken]   = useState('');
  const [tokenizing, setTokenizing]     = useState(false);
  const [browserLaunching, setBrowserLaunching] = useState(false);
  const [dnsAuditing, setDnsAuditing]   = useState(false);
  const [notif, setNotif]   = useState<{msg: string; ok: boolean} | null>(null);
  const [dnsList, setDnsList] = useState<{domain:string;secure:boolean;local_ip:string;secure_ip:string}[]>([]);

  const DNS_DOMAINS = ['sbi.co.in','hdfcbank.com','icicibank.com','axisbank.com','paytm.com','paypal.com'];

  useEffect(() => {
    setDnsList(DNS_DOMAINS.map(d => ({ domain: d, secure: true, local_ip: '', secure_ip: '' })));
  }, []);

  const notify = (msg: string, ok = true) => {
    setNotif({ msg, ok }); setTimeout(() => setNotif(null), 5000);
  };

  const handleTokenize = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!card || !expiry || !cvv) return;
    setTokenizing(true);
    try {
      const res = await api.tokenizeCardData(card, expiry, cvv);
      if (res?.token) { setToken(res.token); notify('Card tokenized via AES-256-GCM on Python backend.'); }
    } catch { notify('Tokenization failed — is the backend running?', false); }
    finally { setTokenizing(false); }
  };

  const handleLaunchBrowser = async (url: string) => {
    setBrowserLaunching(true);
    try {
      const res = await api.launchSecureBrowser(url);
      notify(res?.success ? `Secure browser launched: ${url}` : 'Launch failed.', !!res?.success);
    } catch { notify('Launch failed — is the backend running?', false); }
    finally { setBrowserLaunching(false); }
  };

  const handleDnsAudit = async () => {
    setDnsAuditing(true);
    try {
      const res = await api.auditDns(DNS_DOMAINS);
      if (res?.results) {
        setDnsList(res.results);
        const bad = res.results.filter((r: any) => !r.secure).length;
        notify(bad > 0
          ? `⚠️ DNS poisoning detected for ${bad} domain(s)!`
          : 'All banking domains verified — no spoofing detected.', bad === 0);
      }
    } catch { notify('DNS audit failed — is the backend running?', false); }
    finally { setDnsAuditing(false); }
  };

  const handleWipeClipboard = async () => {
    try { await api.wipeClipboard(); notify('Clipboard wiped via Windows API.'); }
    catch { notify('Wipe failed.', false); }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, overflow: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>Payment Security Shield</h1>
        <span className="badge badge-high" style={{ fontSize: 11 }}>MOD-08 (Tier 5)</span>
      </div>
      <p style={{ color: '#64748b', fontSize: 13, marginBottom: 20 }}>
        Real-time transaction interception, card tokenization, and anti-keylogging sandbox.
      </p>

      <AnimatePresence>
        {notif && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{
              background: notif.ok ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)',
              border: `1px solid ${notif.ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
              borderRadius: 12, padding: '12px 16px', marginBottom: 20,
              color: notif.ok ? '#10b981' : '#ef4444',
              fontSize: 13, display: 'flex', alignItems: 'center', gap: 10,
            }}>
            <span className={`animate-pulse-dot ${notif.ok ? 'dot-green' : 'dot-red'}`} />
            <span style={{ fontWeight: 500 }}>{notif.msg}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 18, marginBottom: 18 }}>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <CreditCard size={20} color="#3b82f6" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Card Tokenizer Sandbox</h3>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
            AVOS tokenizes card details via Python Fernet (AES-256) — raw data never leaves your device.
          </p>
          <form onSubmit={handleTokenize} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input className="input" value={card} onChange={e => setCard(e.target.value)}
              placeholder="Card Number" maxLength={19} required />
            <div style={{ display: 'flex', gap: 10 }}>
              <input className="input" value={expiry} onChange={e => setExpiry(e.target.value)}
                placeholder="Expiry (MM/YY)" maxLength={5} required />
              <input className="input" type="password" value={cvv} onChange={e => setCvv(e.target.value)}
                placeholder="CVV" maxLength={4} required />
            </div>
            <button className="btn btn-primary" type="submit" disabled={tokenizing}
              style={{ width: '100%', justifyContent: 'center' }}>
              {tokenizing ? <RefreshCw size={14} className="animate-spin" /> : 'Tokenize via AVOS Engine'}
            </button>
          </form>
          {token && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              style={{ marginTop: 16, padding: 14, borderRadius: 10, background: 'rgba(79,70,229,0.05)',
                border: '1px dashed rgba(79,70,229,0.3)' }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: '#4f46e5', display: 'block', marginBottom: 6 }}>
                🛡️ AES-256 Token (Python backend)
              </span>
              <div className="mono" style={{ fontSize: 10, wordBreak: 'break-all', color: '#111827' }}>{token}</div>
            </motion.div>
          )}
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <Lock size={20} color="#10b981" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Secure Browser Mode</h3>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
            Isolated incognito browser with extensions and caches disabled — prevents formjacking.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1 }}>
            {['https://www.paypal.com','https://www.icicibank.com','https://netbanking.hdfcbank.com'].map(url => (
              <button key={url} className="btn btn-ghost" onClick={() => handleLaunchBrowser(url)}
                disabled={browserLaunching}
                style={{ justifyContent: 'space-between', fontSize: 12 }}>
                <span className="mono">{url.replace('https://', '')}</span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
          <button className="btn btn-primary" onClick={() => handleLaunchBrowser('https://www.paypal.com')}
            disabled={browserLaunching} style={{ width: '100%', justifyContent: 'center', marginTop: 16 }}>
            {browserLaunching ? <RefreshCw size={14} className="animate-spin" /> : 'Launch Secure Session'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 18 }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <Activity size={20} color="#ef4444" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Clipboard Guard</h3>
            </div>
            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
              Python payment_shield monitors clipboard every 1.5s. Card/UPI data is wiped instantly via Windows API.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px',
              borderRadius: 8, background: '#f8fafc', border: '1px solid rgba(0,0,0,0.05)', marginBottom: 16 }}>
              <span className="animate-pulse-dot dot-green" />
              <div>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#111827', display: 'block' }}>Active Monitoring</span>
                <span style={{ fontSize: 10, color: '#64748b' }}>Python payment_shield running</span>
              </div>
            </div>
          </div>
          <button className="btn btn-danger" onClick={handleWipeClipboard}
            style={{ width: '100%', justifyContent: 'center' }}>Sanitize Clipboard Now</button>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Wifi size={20} color="#06b6d4" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>DNS Spoofing Monitor</h3>
            </div>
            <button className="btn btn-ghost" onClick={handleDnsAudit} disabled={dnsAuditing}
              style={{ padding: '4px 10px', fontSize: 11 }}>
              {dnsAuditing ? <RefreshCw size={12} className="animate-spin" /> : 'Run Audit'}
            </button>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
            Verifies banking domains via Cloudflare DNS-over-HTTPS to detect DNS poisoning attacks.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {dnsList.map(dns => (
              <div key={dns.domain} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 12px', borderRadius: 8, background: '#f8fafc',
                border: `1px solid ${dns.secure ? 'rgba(0,0,0,0.05)' : 'rgba(239,68,68,0.2)'}`,
              }}>
                <div>
                  <span className="mono" style={{ fontSize: 12, color: '#111827' }}>{dns.domain}</span>
                  {dns.local_ip && (
                    <div style={{ fontSize: 10, color: '#94a3b8' }}>
                      Local: {dns.local_ip} · Secure: {dns.secure_ip || '—'}
                    </div>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className={`animate-pulse-dot ${dns.secure ? 'dot-green' : 'dot-red'}`} />
                  <span style={{ fontSize: 11, fontWeight: 600, color: dns.secure ? '#10b981' : '#ef4444' }}>
                    {dns.secure ? 'SECURE' : '⚠️ POISONED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ─── AI Chat ─────────────────────────────────────────────────────────────────
function AIChatPage() {
  const [messages, setMessages] = useState([{
    role: 'assistant',
    text: "👋 Hi! I'm your AVOS AI assistant, powered by your real-time security database.\n\nAsk me about: threats, ransomware, payment security, modules, status, or modes."
  }]);
  const [input, setInput]     = useState('');
  const [loading, setLoading] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  const send = async () => {
    if (!input.trim() || loading) return;
    const q = input.trim();
    setInput('');
    setMessages(m => [...m, { role: 'user', text: q }]);
    setLoading(true);
    try {
      const res = await api.chat(q);
      setMessages(m => [...m, { role: 'assistant', text: res?.answer || 'No response from backend.' }]);
    } catch {
      setMessages(m => [...m, {
        role: 'assistant',
        text: '⚠️ Could not reach the AVOS backend. Ensure Python CSO is running.'
      }]);
    } finally {
      setLoading(false);
      setTimeout(() => endRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>AI Security Assistant</h1>
      <p style={{ color: '#64748b', fontSize: 13, marginBottom: 20 }}>
        Offline expert system — answers use real live data from your security database
      </p>
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 12, padding: '0 0 16px' }}>
          {messages.map((m, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              style={{ display: 'flex', justifyContent: m.role === 'user' ? 'flex-end' : 'flex-start', flexShrink: 0 }}>
              <div style={{
                maxWidth: '80%', padding: '10px 14px', borderRadius: 14,
                background: m.role === 'user' ? '#111827' : '#f3f4f6',
                border: m.role === 'user' ? 'none' : '1px solid rgba(0,0,0,0.05)',
                fontSize: 13, lineHeight: 1.6,
                color: m.role === 'user' ? '#ffffff' : '#111827',
                whiteSpace: 'pre-wrap',
              }}>{m.text}</div>
            </motion.div>
          ))}
          {loading && (
            <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
              <div style={{ padding: '10px 14px', borderRadius: 14, background: '#f3f4f6',
                border: '1px solid rgba(0,0,0,0.05)', color: '#94a3b8', fontSize: 13 }}>
                <RefreshCw size={14} className="animate-spin" style={{ display: 'inline', marginRight: 6 }} />
                Querying security database...
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>
        <div className="sep" style={{ margin: '8px 0' }} />
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input" value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && send()}
            placeholder="Ask about threats, ransomware, payment, status, modules..." />
          <button className="btn btn-primary" onClick={send} disabled={loading}>
            <Brain size={16} />Ask
          </button>
        </div>
      </div>
    </motion.div>
  );
}

// ─── Settings ─────────────────────────────────────────────────────────────────
function SettingsPage({ status, onToggle }: { status: SystemStatus; onToggle: (k: string, e: boolean) => void }) {
  const [toggling, setToggling] = useState<string | null>(null);

  const doToggle = async (key: string, current: boolean) => {
    setToggling(key);
    try { await api.setModuleConfig(key, !current); onToggle(key, !current); }
    catch (e) { console.error(e); }
    finally { setToggling(null); }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, overflow: 'auto', height: '100%' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 20 }}>Settings</h1>
      <div className="card">
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Security Modules</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {Object.entries(status.modules).map(([key, mod]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 0', borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
              <div>
                <div style={{ fontWeight: 500, fontSize: 13 }}>{mod.name}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>
                  {mod.enabled ? 'Active' : 'Disabled'}
                  {toggling === key && ' — updating...'}
                </div>
              </div>
              <div className={`toggle ${mod.enabled ? 'on' : ''}`}
                onClick={() => doToggle(key, mod.enabled)}
                style={{ opacity: toggling === key ? 0.5 : 1, cursor: toggling === key ? 'wait' : 'pointer' }} />
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function UtilitiesPage() {
  const [lockPath, setLockPath] = useState('');
  const [lockPass, setLockPass] = useState('');
  const [msg, setMsg]   = useState<{text: string; ok: boolean} | null>(null);
  const [loading, setLoading] = useState<string | null>(null);

  const notify = (text: string, ok = true) => { setMsg({ text, ok }); setTimeout(() => setMsg(null), 5000); };

  const doScanRegistry = async () => {
    setLoading('registry');
    try { const r = await api.scanRegistry(); notify(r?.message || 'Done.', r?.success); }
    catch { notify('Failed — backend running?', false); }
    finally { setLoading(null); }
  };

  const doCleanTemp = async () => {
    setLoading('temp');
    try { const r = await api.cleanTemp(true); notify(r?.message || 'Done.', r?.success); }
    catch { notify('Failed — backend running?', false); }
    finally { setLoading(null); }
  };

  const doLock = async () => {
    if (!lockPath || !lockPass) { notify('Enter path and password.', false); return; }
    setLoading('lock');
    try { const r = await api.lockFolder(lockPath, lockPass); notify(r?.message || 'Done.', r?.success); }
    catch { notify('Failed — backend running?', false); }
    finally { setLoading(null); }
  };

  const doUnlock = async () => {
    if (!lockPath || !lockPass) { notify('Enter path and password.', false); return; }
    setLoading('unlock');
    try { const r = await api.unlockFolder(lockPath, lockPass); notify(r?.message || 'Done.', r?.success); }
    catch { notify('Failed — backend running?', false); }
    finally { setLoading(null); }
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, overflow: 'auto', height: '100%' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 20 }}>System Utilities</h1>
      {msg && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          style={{
            background: msg.ok ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.12)',
            border: `1px solid ${msg.ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
            borderRadius: 8, padding: '10px 16px', marginBottom: 16,
            color: msg.ok ? '#10b981' : '#ef4444', fontSize: 13,
          }}>
          {msg.text}
        </motion.div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <Database size={20} color="#3b82f6" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Registry Cleaner</h3>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
            Scans Windows registry for orphaned entries left by uninstalled software.
          </p>
          <button className="btn btn-ghost" style={{ width: '100%' }}
            onClick={doScanRegistry} disabled={loading === 'registry'}>
            {loading === 'registry' ? <RefreshCw size={14} className="animate-spin" /> : 'Scan Registry'}
          </button>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <HardDrive size={20} color="#8b5cf6" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Temp Cleaner</h3>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
            Deletes temp files and browser caches from all known system locations.
          </p>
          <button className="btn btn-ghost" style={{ width: '100%' }}
            onClick={doCleanTemp} disabled={loading === 'temp'}>
            {loading === 'temp' ? <RefreshCw size={14} className="animate-spin" /> : 'Clean Now'}
          </button>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <Lock size={20} color="#10b981" /><h3 style={{ fontSize: 14, fontWeight: 600 }}>Folder Lock</h3>
          </div>
          <p style={{ fontSize: 12, color: '#64748b', marginBottom: 12 }}>
            AES-256-GCM encryption with PBKDF2-SHA256 key derivation.
          </p>
          <input className="input" style={{ marginBottom: 8 }} value={lockPath}
            onChange={e => setLockPath(e.target.value)} placeholder="Folder path..." />
          <input className="input" type="password" style={{ marginBottom: 12 }} value={lockPass}
            onChange={e => setLockPass(e.target.value)} placeholder="Password..." />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={doLock} disabled={!!loading}>
              {loading === 'lock' ? <RefreshCw size={14} className="animate-spin" /> : <><Lock size={14} />Lock</>}
            </button>
            <button className="btn btn-ghost" style={{ flex: 1 }} onClick={doUnlock} disabled={!!loading}>
              {loading === 'unlock' ? <RefreshCw size={14} className="animate-spin" /> : 'Unlock'}
            </button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ─── EDR ─────────────────────────────────────────────────────────────────────
function EDRPage() {
  const [events, setEvents]   = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await api.getEDREvents(200); if (r?.events) setEvents(r.events); }
    catch { console.error('EDR load failed'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, overflow: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700 }}>EDR — Forensic Trail</h1>
        <button className="btn btn-ghost" onClick={load} disabled={loading} style={{ fontSize: 12 }}>
          {loading ? <RefreshCw size={14} className="animate-spin" /> : <><RefreshCw size={14} />Refresh</>}
        </button>
      </div>
      <p style={{ color: '#64748b', fontSize: 13, marginBottom: 20 }}>
        Full attack timelines from the live security database
      </p>
      <div className="card">
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Attack Timeline</h3>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>
            <RefreshCw size={24} className="animate-spin" style={{ marginBottom: 8 }} />
            <div>Loading forensic data...</div>
          </div>
        ) : events.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>
            <Eye size={32} color="#10b981" style={{ marginBottom: 8 }} />
            <div>No security events recorded yet.</div>
          </div>
        ) : (
          <div style={{ position: 'relative', paddingLeft: 24 }}>
            <div style={{ position: 'absolute', left: 7, top: 0, bottom: 0, width: 2,
              background: 'linear-gradient(to bottom, #3b82f6, transparent)' }} />
            {events.map((e, i) => (
              <div key={i} style={{ display: 'flex', gap: 16, marginBottom: 20, position: 'relative' }}>
                <div style={{ position: 'absolute', left: -21, width: 12, height: 12, borderRadius: '50%',
                  background: '#3b82f6', border: '2px solid var(--bg-primary)', top: 4 }} />
                <div style={{ flex: 1, background: '#f8fafc', border: '1px solid rgba(0,0,0,0.05)',
                  borderRadius: 12, padding: 14 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#4f46e5',
                      background: 'rgba(79,70,229,0.1)', padding: '2px 8px', borderRadius: 4 }}>
                      {e.event_type}
                    </span>
                    {e.pid > 0 && <span className="mono" style={{ color: '#64748b', fontSize: 11 }}>PID: {e.pid}</span>}
                  </div>
                  {e.path && <div className="mono" style={{ fontSize: 11, color: '#374151', marginBottom: 4 }}>{e.path}</div>}
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {new Date(e.timestamp * 1000).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Firewall ─────────────────────────────────────────────────────────────────
function FirewallPage() {
  const [rules, setRules]   = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterDir, setFilterDir] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await api.getFirewallRules(); if (r?.rules) setRules(r.rules); }
    catch { console.error('Firewall load failed'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = rules.filter(r => {
    const ms = !search || r.name.toLowerCase().includes(search.toLowerCase());
    const md = !filterDir || r.direction === filterDir;
    return ms && md;
  });

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      style={{ padding: 24, overflow: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700 }}>Firewall Rules</h1>
          <p style={{ color: '#64748b', fontSize: 13 }}>Live Windows Firewall rules via netsh</p>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading} style={{ fontSize: 12 }}>
          {loading ? <RefreshCw size={14} className="animate-spin" /> : <><RefreshCw size={14} />Refresh</>}
        </button>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1, maxWidth: 300 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#94a3b8' }} />
          <input className="input" style={{ paddingLeft: 32 }} value={search}
            onChange={e => setSearch(e.target.value)} placeholder="Search rules..." />
        </div>
        {['', 'IN', 'OUT'].map(d => (
          <button key={d} onClick={() => setFilterDir(d)}
            className={`btn ${filterDir === d ? 'btn-primary' : 'btn-ghost'}`}
            style={{ padding: '5px 12px', fontSize: 11 }}>{d || 'All'}</button>
        ))}
        <span style={{ fontSize: 12, color: '#64748b' }}>{filtered.length} rules</span>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>
            <RefreshCw size={24} className="animate-spin" style={{ marginBottom: 8 }} />
            <div>Loading Windows Firewall rules via netsh...</div>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>
            {search ? 'No rules match.' : 'No firewall rules found.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ color: '#64748b', borderBottom: '1px solid rgba(0,0,0,0.05)', background: '#f8fafc' }}>
                {['Rule Name', 'Dir', 'Action', 'Protocol', 'Port', 'Profile', 'Status'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 500, fontSize: 11 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 100).map((r, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(0,0,0,0.04)' }}>
                  <td style={{ padding: '9px 14px', fontWeight: 500, maxWidth: 240,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.name}</td>
                  <td style={{ padding: '9px 14px' }}>
                    <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4,
                      background: r.direction === 'IN' ? 'rgba(6,182,212,0.15)' : 'rgba(139,92,246,0.15)',
                      color: r.direction === 'IN' ? '#06b6d4' : '#8b5cf6' }}>{r.direction}</span>
                  </td>
                  <td style={{ padding: '9px 14px' }}>
                    <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4,
                      background: r.action === 'ALLOW' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                      color: r.action === 'ALLOW' ? '#10b981' : '#ef4444' }}>{r.action}</span>
                  </td>
                  <td style={{ padding: '9px 14px', color: '#64748b' }}>{r.protocol || 'Any'}</td>
                  <td><span className="mono" style={{ fontSize: 11 }}>{r.port || '*'}</span></td>
                  <td style={{ padding: '9px 14px', color: '#64748b', fontSize: 11 }}>{r.profile || '—'}</td>
                  <td style={{ padding: '9px 14px' }}>
                    <span className={`animate-pulse-dot ${r.enabled ? 'dot-green' : 'dot-red'}`} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {filtered.length > 100 && (
        <div style={{ textAlign: 'center', color: '#94a3b8', fontSize: 12, marginTop: 12 }}>
          Showing 100 of {filtered.length}. Use search to filter.
        </div>
      )}
    </motion.div>
  );
}

// ─── App Root ─────────────────────────────────────────────────────────────────
function App() {
  const [status, setStatus]       = useState<SystemStatus | null>(null);
  const [threats, setThreats]     = useState<ThreatEvent[]>([]);
  const [mode, setMode]           = useState('normal');
  const [connectError, setConnectError] = useState('');
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    // Show error if no connection after 12s
    timeoutRef.current = setTimeout(() => {
      setConnectError('Cannot connect to AVOS backend.\n\nRun: python -m core.cso.orchestrator\n(in the Avos_AiAv directory)');
    }, 12000);

    // Subscribe to status updates (real-time IPC in Electron, polling in browser)
    const unsubStatus = api.subscribeStatus((raw: any) => {
      const s = normalizeStatus(raw);
      setStatus(s);
      if (s.mode) setMode(s.mode);
      // Clear error timeout on successful connection
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      setConnectError('');
    });

    // Subscribe to threat stream
    const unsubThreats = api.subscribeThreatStream((t: any) => {
      setThreats(prev => [t, ...prev].slice(0, 200));
    });

    // Load initial threat history from DB
    const loadInitial = async () => {
      try {
        const res = await api.getThreats(100, 0, '');
        if (res?.threats?.length > 0) setThreats(res.threats);
      } catch { /* backend not yet up */ }
    };
    setTimeout(loadInitial, 800);

    return () => {
      unsubStatus();
      unsubThreats();
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const onToggle = (name: string, enabled: boolean) => {
    setStatus(prev => prev ? {
      ...prev,
      modules: { ...prev.modules, [name]: { ...prev.modules[name], enabled } }
    } : prev);
  };

  const onQuarantine = (path: string) => {
    setThreats(prev => prev.map(t => t.path === path ? { ...t, remediated: true } : t));
  };

  const onModeChange = async (m: string) => {
    try { await api.setMode(m); setMode(m); }
    catch (e) { console.error(e); }
  };

  if (!status) {
    return (
      <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-primary)', color: '#64748b' }}>
        <div style={{ textAlign: 'center', maxWidth: 420 }}>
          <div className="animate-spin" style={{
            width: 40, height: 40, border: '3px solid #111827',
            borderTopColor: 'transparent', borderRadius: '50%', margin: '0 auto 20px'
          }} />
          <div style={{ fontSize: 15, fontWeight: 700, color: '#111827', marginBottom: 8 }}>
            Connecting to AVOS CSO...
          </div>
          {connectError ? (
            <div style={{ fontSize: 12, color: '#ef4444', background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '14px 16px',
              marginTop: 8, whiteSpace: 'pre-wrap', textAlign: 'left', lineHeight: 1.7 }}>
              {connectError}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: '#94a3b8' }}>
              Polling http://127.0.0.1:8765/api/status...
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', position: 'relative', zIndex: 1 }}>
        <Sidebar mode={mode} onModeChange={onModeChange} />
        <main style={{ flex: 1, overflow: 'auto' }}>
          <AnimatePresence mode="wait">
            <Routes>
              <Route path="/"          element={<Dashboard status={status} threats={threats} />} />
              <Route path="/threats"   element={<ThreatsPage threats={threats} onQuarantine={onQuarantine} />} />
              <Route path="/firewall"  element={<FirewallPage />} />
              <Route path="/payment"   element={<PaymentShieldPage />} />
              <Route path="/ai-chat"   element={<AIChatPage />} />
              <Route path="/edr"       element={<EDRPage />} />
              <Route path="/utilities" element={<UtilitiesPage />} />
              <Route path="/settings"  element={<SettingsPage status={status} onToggle={onToggle} />} />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
