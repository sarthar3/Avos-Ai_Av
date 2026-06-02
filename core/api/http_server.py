"""
AVOS — HTTP REST Bridge (Browser Mode)
Provides a REST API on port 8765 so the React UI can connect
directly from a browser (without Electron's IPC bridge).

Uses only Python built-ins — no additional packages required.
"""

import asyncio
import json
import logging
import socket
import subprocess
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger('AVOS.HTTP')

PORT = 8765

# ─── CORS helper headers ──────────────────────────────────────────────────────
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
}


def _json(data: Any) -> bytes:
    return json.dumps(data, default=str).encode('utf-8')


# ─── Request Handler ──────────────────────────────────────────────────────────
class AVOSRequestHandler(BaseHTTPRequestHandler):

    # Injected by AVOSHTTPServer after construction
    orchestrator = None

    def log_message(self, format, *args):
        pass  # Suppress default access log (too noisy)

    def _send(self, data: Any, status: int = 200):
        body = _json(data)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        if length > 0:
            try:
                return json.loads(self.rfile.read(length))
            except Exception:
                pass
        return {}

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        orc = self.orchestrator

        try:
            if path == '/api/status':
                import psutil
                status = orc.get_status()
                cpu = psutil.cpu_percent(interval=0.1)
                ram = psutil.Process().memory_info().rss / 1024 / 1024
                modules_list = [
                    {'name': mod['name'], 'enabled': mod['enabled'], 'healthy': mod['healthy'], 'last_event_time': mod['last_event_time']}
                    for mod in status['modules'].values()
                ]
                self._send({
                    'version': status['version'],
                    'mode': status['mode'],
                    'running': status['running'],
                    'modules': modules_list,
                    'threats_today': orc.db.get_threats_today(),
                    'cpu_usage': cpu,
                    'ram_usage_mb': ram,
                })

            elif path == '/api/threats':
                qs = parse_qs(parsed.query)
                limit  = int(qs.get('limit', ['100'])[0])
                offset = int(qs.get('offset', ['0'])[0])
                filt   = qs.get('filter', [''])[0]
                rows = orc.db.get_threats(limit, offset, filt)
                self._send({'threats': rows, 'total': len(rows)})

            elif path == '/api/breach-alerts':
                alerts = orc.dark_web.get_alerts()
                self._send({'alerts': alerts})

            elif path == '/api/edr-events':
                qs = parse_qs(parsed.query)
                limit = int(qs.get('limit', ['200'])[0])
                events = orc.db.get_events(limit)
                self._send({'events': events, 'total': len(events)})

            elif path == '/api/firewall-rules':
                rules = self._fetch_firewall_rules()
                self._send({'rules': rules})

            else:
                self._send({'error': 'Not found'}, 404)

        except Exception as e:
            logger.error(f"GET {path} error: {e}")
            self._send({'error': str(e)}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_body()
        orc = self.orchestrator

        try:
            if path == '/api/mode':
                orc.set_mode(body.get('mode', 'normal'))
                self._send({'success': True})

            elif path == '/api/module-config':
                name = body.get('name', '')
                enabled = bool(body.get('enabled', True))
                if name in orc.modules:
                    orc.modules[name].enabled = enabled
                    self._send({'success': True, 'message': f"Module {name} {'enabled' if enabled else 'disabled'}"})
                else:
                    self._send({'success': False, 'message': f'Unknown module: {name}'}, 400)

            elif path == '/api/chat':
                question = body.get('question', '').lower().strip()
                answer, confidence = self._build_chat_answer(question, orc)
                self._send({'answer': answer, 'confidence': confidence})

            elif path == '/api/tokenize':
                token = orc.payment_shield.tokenize(
                    body.get('card', ''), body.get('exp', ''), body.get('cvv', '')
                )
                self._send({'token': token})

            elif path == '/api/wipe-clipboard':
                orc.payment_shield.wipe_clipboard()
                self._send({'success': True, 'message': 'Clipboard wiped'})

            elif path == '/api/launch-browser':
                success = orc.payment_shield.launch_secure_browser(body.get('url', 'https://www.paypal.com'))
                self._send({'success': success})

            elif path == '/api/quarantine':
                file_path = body.get('path', '')
                if file_path:
                    # Run in background thread since _quarantine is async
                    import shutil
                    from pathlib import Path
                    q_path = Path(orc.config.get('quarantine_path', 'quarantine'))
                    q_path.mkdir(parents=True, exist_ok=True)
                    shutil.move(file_path, str(q_path / Path(file_path).name))
                    self._send({'success': True, 'message': f'Quarantined: {file_path}'})
                else:
                    self._send({'success': False, 'message': 'No path provided'}, 400)

            elif path == '/api/scan-file':
                file_path = body.get('path', '')
                if not file_path:
                    self._send({'is_threat': False, 'score': 0, 'threat_name': '', 'explanation': 'No path'})
                    return
                sig_res = orc.sig_engine.scan(file_path)
                if sig_res.is_threat:
                    self._send({'is_threat': True, 'score': 100.0, 'threat_name': sig_res.signature_name,
                                'explanation': f'Known malware: {sig_res.signature_name}'})
                else:
                    h_res = orc.heuristic.analyze(file_path)
                    self._send({'is_threat': h_res.score >= 60, 'score': h_res.score,
                                'threat_name': 'Suspicious' if h_res.score >= 60 else '',
                                'explanation': h_res.explanation or 'File appears clean.'})

            elif path == '/api/audit-dns':
                domains = body.get('domains', [
                    'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
                    'axisbank.com', 'paytm.com', 'paypal.com'
                ])
                results = []
                ps = orc.payment_shield
                for domain in domains:
                    local_ip  = ps._get_local_ip(domain)  or ''
                    secure_ip = ps._get_secure_ip(domain) or ''
                    secure = True
                    if local_ip and secure_ip:
                        secure = (local_ip == secure_ip)
                    results.append({
                        'domain': domain, 'secure': secure,
                        'local_ip': local_ip, 'secure_ip': secure_ip
                    })
                self._send({'results': results})

            elif path == '/api/scan-registry':
                from core.utilities.utilities import RegistryCleaner
                orphans = RegistryCleaner().scan()
                self._send({'success': True, 'message': f'Found {len(orphans)} orphaned registry entries',
                            'count': len(orphans), 'size_mb': 0.0})

            elif path == '/api/clean-temp':
                from core.utilities.utilities import TempCleaner
                include_browser = body.get('include_browser_cache', True)
                files, freed = TempCleaner().clean(include_browser)
                self._send({'success': True,
                            'message': f'Deleted {files} files, freed {freed/(1024**2):.1f} MB',
                            'count': files, 'size_mb': freed / (1024 * 1024)})

            elif path == '/api/lock-folder':
                from core.utilities.utilities import FolderLock
                ok, msg = FolderLock().lock_folder(body.get('path', ''), body.get('password', ''))
                self._send({'success': ok, 'message': msg})

            elif path == '/api/unlock-folder':
                from core.utilities.utilities import FolderLock
                ok, msg = FolderLock().unlock_folder(body.get('path', ''), body.get('password', ''))
                self._send({'success': ok, 'message': msg})

            else:
                self._send({'error': 'Not found'}, 404)

        except Exception as e:
            logger.error(f"POST {path} error: {e}")
            self._send({'error': str(e)}, 500)

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _fetch_firewall_rules(self):
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'verbose'],
                capture_output=True, text=True, timeout=15
            )
            return self._parse_netsh(result.stdout)
        except Exception as e:
            logger.error(f"Firewall fetch error: {e}")
            return []

    def _parse_netsh(self, text: str):
        rules = []
        blocks = re.split(r'\n(?=Rule Name:)', text)
        for block in blocks:
            if 'Rule Name:' not in block:
                continue
            def _get(field):
                m = re.search(rf'^{re.escape(field)}:\s*(.+)$', block, re.MULTILINE)
                return m.group(1).strip() if m else ''
            name = _get('Rule Name')
            if not name:
                continue
            rules.append({
                'name':      name,
                'direction': (_get('Direction') or '?')[:3].upper(),
                'action':    (_get('Action') or '?')[:5].upper(),
                'port':      _get('LocalPort') or _get('RemotePort') or '*',
                'enabled':   _get('Enabled').lower() == 'yes',
                'protocol':  _get('Protocol'),
                'profile':   _get('Profiles'),
            })
            if len(rules) >= 200:
                break
        return rules

    def _build_chat_answer(self, question: str, orc) -> tuple:
        """Same offline expert system as grpc_server.py but synchronous."""
        db = orc.db
        threats_today = db.get_threats_today()
        recent = db.get_threats(limit=5, offset=0, level_filter='')
        active_modules = sum(1 for m in orc.modules.values() if m.enabled)
        total_modules  = len(orc.modules)
        mode = orc.mode.value
        forensic_stats = orc.forensic.get_process_stats()

        if any(k in question for k in ['status', 'safe', 'protect', 'ok', 'health']):
            return (
                f"✅ AVOS is fully operational in **{mode}** mode.\n"
                f"• **{active_modules}/{total_modules}** security modules active\n"
                f"• **{threats_today}** threats detected today\n"
                f"• **{forensic_stats['total_events']}** total events logged in EDR",
                0.97
            )

        if any(k in question for k in ['threat', 'attack', 'recent', 'detect']):
            if recent:
                lines = "\n".join(f"• [{r['threat_level']}] {r['event_type'].replace('_',' ')} — {r['explanation'][:80]}..." for r in recent[:3])
                return (f"🔴 **{threats_today}** threats today. Recent:\n{lines}", 0.95)
            return ("✅ No threats recorded. System is clean.", 0.95)

        if any(k in question for k in ['ransomware', 'encrypt']):
            return ("🛡️ Ransomware Shield monitors file write velocity. >50 files in 10s triggers process termination and quarantine.", 0.92)

        if any(k in question for k in ['payment', 'card', 'upi', 'bank', 'clipboard']):
            return ("💳 Payment Shield monitors clipboard, verifies banking DNS via Cloudflare DoH, tokenizes cards with AES-256, and launches isolated browser sessions.", 0.94)

        if any(k in question for k in ['mode', 'gamer', 'developer']):
            return (f"⚙️ Currently in **{mode.upper()}** mode. Normal=full, Gamer=no file scan, Developer=raw logs+whitelist.", 0.93)

        if any(k in question for k in ['module', 'enable', 'disable']):
            disabled = [m.name for m in orc.modules.values() if not m.enabled]
            if disabled:
                return (f"⚠️ Disabled: {', '.join(disabled)}. Re-enable in Settings.", 0.88)
            return ("✅ All modules active.", 0.92)

        return (
            f"AVOS: **{threats_today}** threats today, **{active_modules}/{total_modules}** modules active in **{mode}** mode.\n"
            "Ask about: threats, ransomware, payment, memory, rootkit, modes, modules, or status.",
            0.70
        )


# ─── Server Wrapper ───────────────────────────────────────────────────────────

class AVOSHTTPServer:
    """Runs a simple HTTP REST bridge on port 8765 in a background thread."""

    def __init__(self, orchestrator, port: int = PORT):
        self.orchestrator = orchestrator
        self.port = port
        self._server = None
        self._thread = None

    def start(self):
        # Inject orchestrator reference into handler class
        handler = type('Handler', (AVOSRequestHandler,), {'orchestrator': self.orchestrator})

        self._server = HTTPServer(('0.0.0.0', self.port), handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"AVOS HTTP REST bridge listening on http://localhost:{self.port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
