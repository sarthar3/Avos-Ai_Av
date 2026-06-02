"""
AVOS — gRPC Service Implementation
All RPC handlers wired to real Python backend modules.
"""

import asyncio
import json
import logging
import subprocess
import re
import socket
import time
from concurrent import futures
from typing import AsyncIterable

import grpc
import psutil

# Import generated stubs
import shared.proto.avos_pb2 as pb2
import shared.proto.avos_pb2_grpc as pb2_grpc

logger = logging.getLogger('AVOS.GRPC')


class AvosServiceServicer(pb2_grpc.AvosServiceServicer):
    """Full implementation of the Avos gRPC service."""

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.event_queues = []

    # ─── Streaming ────────────────────────────────────────────────────────────

    async def StreamThreatEvents(self, request, context) -> AsyncIterable[pb2.ThreatEventProto]:
        """Streams real-time threat events to connected UI clients."""
        logger.info("New UI client subscribed to threat stream.")
        queue = asyncio.Queue()
        self.event_queues.append(queue)
        try:
            while True:
                event = await queue.get()
                yield pb2.ThreatEventProto(
                    event_id     = event.event_id,
                    event_type   = event.event_type,
                    threat_level = event.threat_level.name,
                    score        = event.score,
                    source       = event.source,
                    path         = event.path or "",
                    pid          = event.pid or 0,
                    details_json = json.dumps(event.details),
                    timestamp    = event.timestamp,
                    remediated   = event.remediated,
                    explanation  = event.explanation
                )
        finally:
            self.event_queues.remove(queue)
            logger.info("UI client unsubscribed from threat stream.")

    async def broadcast_threat(self, threat):
        """Helper: push a real ThreatEvent to all connected UI clients."""
        for queue in self.event_queues:
            await queue.put(threat)

    # ─── Status ───────────────────────────────────────────────────────────────

    async def GetSystemStatus(self, request, context):
        status = self.orchestrator.get_status()
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.Process().memory_info().rss / 1024 / 1024

        modules = []
        for name, mod in status['modules'].items():
            modules.append(pb2.ModuleStatusProto(
                name           = mod['name'],
                enabled        = mod['enabled'],
                healthy        = mod['healthy'],
                last_event_time = mod['last_event_time'] or 0.0
            ))

        return pb2.SystemStatus(
            version      = status['version'],
            mode         = status['mode'],
            running      = status['running'],
            modules      = modules,
            threats_today = self.orchestrator.db.get_threats_today(),
            cpu_usage    = cpu,
            ram_usage_mb = ram
        )

    # ─── Mode / Module Config ─────────────────────────────────────────────────

    async def SetMode(self, request, context):
        self.orchestrator.set_mode(request.mode)
        return pb2.GenericResponse(success=True, message=f"Mode set to {request.mode}")

    async def SetModuleConfig(self, request, context):
        name = request.module_name
        if name in self.orchestrator.modules:
            self.orchestrator.modules[name].enabled = request.enabled
            action = "enabled" if request.enabled else "disabled"
            logger.info(f"Module '{name}' {action} via gRPC.")
            return pb2.GenericResponse(success=True, message=f"Module {name} {action}")
        return pb2.GenericResponse(success=False, message=f"Unknown module: {name}")

    # ─── Threats ──────────────────────────────────────────────────────────────

    async def GetThreats(self, request, context):
        limit  = request.limit  or 100
        offset = request.offset or 0
        filt   = request.filter or ""
        rows   = await asyncio.to_thread(
            self.orchestrator.db.get_threats, limit, offset, filt
        )
        threats = []
        for r in rows:
            threats.append(pb2.ThreatEventProto(
                event_id     = r.get('event_id', ''),
                event_type   = r.get('event_type', ''),
                threat_level = r.get('threat_level', 'UNKNOWN'),
                score        = float(r.get('score', 0.0)),
                source       = r.get('source', ''),
                path         = r.get('path') or '',
                pid          = r.get('pid') or 0,
                details_json = r.get('details_json') or '{}',
                timestamp    = float(r.get('timestamp', 0.0)),
                remediated   = bool(r.get('remediated', False)),
                explanation  = r.get('explanation', '')
            ))
        return pb2.ThreatListResponse(threats=threats, total=len(threats))

    async def QuarantineFile(self, request, context):
        path = request.path
        if not path:
            return pb2.GenericResponse(success=False, message="No path provided")
        try:
            await self.orchestrator._quarantine(path)
            return pb2.GenericResponse(success=True, message=f"Quarantined: {path}")
        except Exception as e:
            return pb2.GenericResponse(success=False, message=str(e))

    # ─── On-Demand Scan ───────────────────────────────────────────────────────

    async def ScanFile(self, request, context):
        path = request.path
        if not path:
            return pb2.ScanResponse(is_threat=False, score=0, threat_name="", explanation="No path provided")

        # Signature check
        sig_res = await asyncio.to_thread(self.orchestrator.sig_engine.scan, path)
        if sig_res.is_threat:
            return pb2.ScanResponse(
                is_threat  = True,
                score      = 100.0,
                threat_name = sig_res.signature_name,
                explanation = f"Known malware signature matched: {sig_res.signature_name}"
            )

        # Heuristic check
        h_res = await asyncio.to_thread(self.orchestrator.heuristic.analyze, path)
        return pb2.ScanResponse(
            is_threat  = h_res.score >= 60.0,
            score      = h_res.score,
            threat_name = "Suspicious file" if h_res.score >= 60.0 else "",
            explanation = h_res.explanation or "File appears clean."
        )

    # ─── AI Chat (Offline, DB-Context Aware) ─────────────────────────────────

    async def Chat(self, request, context):
        question = request.question.lower().strip()
        answer, confidence = await asyncio.to_thread(self._build_chat_answer, question)
        return pb2.ChatResponse(answer=answer, confidence=confidence)

    def _build_chat_answer(self, question: str) -> tuple:
        """Offline expert system: pulls real data from DB to answer questions."""
        db = self.orchestrator.db
        orc = self.orchestrator

        # Real stats from DB
        threats_today = db.get_threats_today()
        recent = db.get_threats(limit=5, offset=0, level_filter='')
        total_modules = len(orc.modules)
        active_modules = sum(1 for m in orc.modules.values() if m.enabled)
        mode = orc.mode.value
        forensic_stats = orc.forensic.get_process_stats()

        # Keyword routing with real data
        if any(k in question for k in ['status', 'safe', 'protect', 'ok', 'health']):
            return (
                f"✅ AVOS is fully operational in **{mode}** mode.\n"
                f"• **{active_modules}/{total_modules}** security modules active\n"
                f"• **{threats_today}** threats detected today\n"
                f"• **{forensic_stats['total_events']}** total events logged in EDR\n"
                f"• **{forensic_stats['total_processes_tracked']}** processes tracked",
                0.97
            )

        if any(k in question for k in ['threat', 'attack', 'recent', 'last', 'detect']):
            if recent:
                lines = "\n".join(
                    f"• [{r['threat_level']}] {r['event_type'].replace('_',' ')} — {r['explanation'][:80]}..."
                    for r in recent[:3]
                )
                return (
                    f"🔴 **{threats_today}** threats detected today. Most recent:\n{lines}",
                    0.95
                )
            return ("✅ No threats recorded yet. Your system is clean.", 0.95)

        if any(k in question for k in ['ransomware', 'encrypt', 'file lock']):
            return (
                "🛡️ **Ransomware Shield** monitors file write velocity. If >50 files are modified in 10 seconds, "
                "the responsible process is immediately terminated and a quarantine is triggered. "
                "Shadow copy rollback is initiated if VSS is available.",
                0.92
            )

        if any(k in question for k in ['payment', 'card', 'upi', 'bank', 'clipboard']):
            return (
                "💳 **Payment Shield** actively monitors:\n"
                "• Clipboard — wipes card/UPI data if copied\n"
                "• DNS — verifies banking domains against Cloudflare DoH\n"
                "• Card Tokenizer — AES-256-GCM local encryption before any transmission\n"
                "• Secure Browser — isolated incognito sandbox for banking sessions",
                0.94
            )

        if any(k in question for k in ['memory', 'inject', 'dll', 'process']):
            return (
                "🧠 **Memory Guard** scans running process memory regions for shellcode, "
                "DLL injection patterns, and anomalous write attempts into protected processes (LSASS, etc). "
                "Suspicious processes are flagged and optionally suspended.",
                0.91
            )

        if any(k in question for k in ['rootkit', 'hidden', 'stealth', 'kernel']):
            return (
                "🔍 **Rootkit Detector** performs cross-view comparison:\n"
                "• Compares OS-reported process list vs. raw kernel enumeration\n"
                "• Detects hidden drivers and SSDT hooks\n"
                "• Alerts on any discrepancy between userland and kernel views",
                0.90
            )

        if any(k in question for k in ['mode', 'gamer', 'developer', 'normal']):
            return (
                f"⚙️ Currently in **{mode.upper()}** mode.\n"
                "• **Normal** — full protection, all modules active\n"
                "• **Gamer** — file scan paused during gaming (zero overhead)\n"
                "• **Developer** — raw event logs + process whitelisting active",
                0.93
            )

        if any(k in question for k in ['module', 'enable', 'disable', 'setting']):
            disabled = [m.name for m in orc.modules.values() if not m.enabled]
            if disabled:
                return (f"⚠️ Disabled modules: {', '.join(disabled)}. Re-enable them in Settings.", 0.88)
            return ("✅ All security modules are currently active and healthy.", 0.92)

        if any(k in question for k in ['dark web', 'breach', 'leak', 'hibp', 'password']):
            alerts = orc.dark_web.get_alerts()
            if alerts:
                return (
                    f"🚨 **{len(alerts)}** breach alert(s) found in monitored email accounts.\n"
                    f"Most recent: {alerts[0].get('source','?')} ({alerts[0].get('breach_date','?')})\n"
                    "Review the EDR section for full details.",
                    0.94
                )
            return ("✅ No credential breaches detected for monitored email addresses.", 0.93)

        if any(k in question for k in ['edr', 'forensic', 'timeline', 'log']):
            return (
                f"📋 **EDR Forensic Trail** stats:\n"
                f"• {forensic_stats['total_processes_tracked']} processes tracked\n"
                f"• {forensic_stats['total_events']} events recorded\n"
                f"• {forensic_stats['zero_trust_policies']} zero-trust network policies active\n"
                "Visit the EDR page to see the full attack timeline.",
                0.92
            )

        # Generic fallback with real context
        return (
            f"I'm the AVOS offline security assistant. Your system currently has "
            f"**{threats_today}** threats today with **{active_modules}/{total_modules}** modules active.\n\n"
            "Ask me about: **threats**, **ransomware**, **payment**, **memory**, **rootkit**, "
            "**dark web**, **modes**, **modules**, or **status**.",
            0.70
        )

    # ─── Breach Alerts ────────────────────────────────────────────────────────

    async def GetBreachAlerts(self, request, context):
        rows = await asyncio.to_thread(self.orchestrator.dark_web.get_alerts)
        alerts = [
            pb2.BreachAlert(
                email      = r.get('email', ''),
                source     = r.get('source', ''),
                date       = r.get('breach_date', ''),
                data_types = r.get('data_types', '')
            )
            for r in rows
        ]
        return pb2.BreachListResponse(alerts=alerts)

    # ─── Payment Shield ───────────────────────────────────────────────────────

    async def LaunchSecureBrowser(self, request, context):
        logger.info(f"gRPC: launch secure browser → {request.url}")
        success = await asyncio.to_thread(
            self.orchestrator.payment_shield.launch_secure_browser, request.url
        )
        return pb2.GenericResponse(
            success = success,
            message = "Secure browser launched" if success else "No browser executable found"
        )

    async def TokenizeCardData(self, request, context):
        token = await asyncio.to_thread(
            self.orchestrator.payment_shield.tokenize,
            request.card_number, request.expiry, request.cvv
        )
        return pb2.TokenizeResponse(token=token)

    async def WipeClipboard(self, request, context):
        await asyncio.to_thread(self.orchestrator.payment_shield.wipe_clipboard)
        return pb2.GenericResponse(success=True, message="Clipboard securely wiped")

    # ─── DNS Audit ────────────────────────────────────────────────────────────

    async def AuditDns(self, request, context):
        domains = list(request.domains) or [
            "sbi.co.in", "hdfcbank.com", "icicibank.com",
            "axisbank.com", "paytm.com", "phonepe.com",
            "paypal.com", "razorpay.com"
        ]
        results = await asyncio.to_thread(self._run_dns_audit, domains)
        return pb2.DnsAuditResponse(results=results)

    def _run_dns_audit(self, domains):
        ps = self.orchestrator.payment_shield
        out = []
        for domain in domains:
            local_ip  = ps._get_local_ip(domain)  or ""
            secure_ip = ps._get_secure_ip(domain) or ""
            secure = True
            if local_ip and secure_ip:
                secure = (local_ip == secure_ip)
            out.append(pb2.DnsAuditEntry(
                domain   = domain,
                secure   = secure,
                local_ip = local_ip,
                secure_ip = secure_ip
            ))
        return out

    # ─── Utilities ────────────────────────────────────────────────────────────

    async def ScanRegistry(self, request, context):
        from core.utilities.utilities import RegistryCleaner
        try:
            orphans = await asyncio.to_thread(RegistryCleaner().scan)
            return pb2.UtilityResponse(
                success = True,
                message = f"Found {len(orphans)} orphaned registry entries",
                count   = len(orphans),
                size_mb = 0.0
            )
        except Exception as e:
            return pb2.UtilityResponse(success=False, message=str(e))

    async def CleanTemp(self, request, context):
        from core.utilities.utilities import TempCleaner
        try:
            files, freed = await asyncio.to_thread(
                TempCleaner().clean, request.include_browser_cache
            )
            return pb2.UtilityResponse(
                success = True,
                message = f"Deleted {files} files, freed {freed/(1024**2):.1f} MB",
                count   = files,
                size_mb = freed / (1024 * 1024)
            )
        except Exception as e:
            return pb2.UtilityResponse(success=False, message=str(e))

    async def LockFolder(self, request, context):
        from core.utilities.utilities import FolderLock
        try:
            ok, msg = await asyncio.to_thread(
                FolderLock().lock_folder, request.path, request.password
            )
            return pb2.GenericResponse(success=ok, message=msg)
        except Exception as e:
            return pb2.GenericResponse(success=False, message=str(e))

    async def UnlockFolder(self, request, context):
        from core.utilities.utilities import FolderLock
        try:
            ok, msg = await asyncio.to_thread(
                FolderLock().unlock_folder, request.path, request.password
            )
            return pb2.GenericResponse(success=ok, message=msg)
        except Exception as e:
            return pb2.GenericResponse(success=False, message=str(e))

    # ─── Firewall Rules (real Windows Firewall via netsh) ─────────────────────

    async def GetFirewallRules(self, request, context):
        rules = await asyncio.to_thread(self._fetch_firewall_rules)
        return pb2.FirewallRulesResponse(rules=rules)

    def _fetch_firewall_rules(self):
        """Parse real Windows Firewall rules via netsh advfirewall."""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'verbose'],
                capture_output=True, text=True, timeout=15
            )
            return self._parse_netsh_output(result.stdout)
        except Exception as e:
            logger.error(f"Firewall fetch error: {e}")
            return []

    def _parse_netsh_output(self, text: str):
        """Parse netsh rule blocks into FirewallRule protos."""
        rules = []
        blocks = re.split(r'\n(?=Rule Name:)', text)
        for block in blocks:
            if 'Rule Name:' not in block:
                continue
            def _get(field):
                m = re.search(rf'^{re.escape(field)}:\s*(.+)$', block, re.MULTILINE)
                return m.group(1).strip() if m else ''

            name      = _get('Rule Name')
            direction = _get('Direction')
            action    = _get('Action')
            enabled   = _get('Enabled').lower() == 'yes'
            port      = _get('LocalPort') or _get('RemotePort') or '*'
            protocol  = _get('Protocol')
            profile   = _get('Profiles')

            if not name:
                continue

            rules.append(pb2.FirewallRule(
                name      = name,
                direction = direction.upper()[:3] if direction else '?',
                action    = action.upper()[:5] if action else '?',
                port      = port,
                enabled   = enabled,
                protocol  = protocol,
                profile   = profile
            ))

            # Cap at 200 rules for UI performance
            if len(rules) >= 200:
                break
        return rules

    # ─── EDR Events ──────────────────────────────────────────────────────────

    async def GetEDREvents(self, request, context):
        limit = request.limit or 200
        rows = await asyncio.to_thread(
            self.orchestrator.db.get_events, limit
        )
        events = [
            pb2.EDREvent(
                event_type   = r.get('event_type', ''),
                pid          = r.get('pid') or 0,
                path         = r.get('path') or '',
                details_json = r.get('details_json') or '{}',
                timestamp    = float(r.get('timestamp', 0.0))
            )
            for r in rows
        ]
        return pb2.EDREventsResponse(events=events, total=len(events))


# ─── gRPC Server Wrapper ─────────────────────────────────────────────────────

class GRPCServer:
    """Async gRPC server wrapper."""

    def __init__(self, orchestrator, port=50051):
        self.orchestrator = orchestrator
        self.port = port
        self.server = None
        self.servicer = None

    async def start(self):
        self.server = grpc.aio.server()
        self.servicer = AvosServiceServicer(self.orchestrator)
        pb2_grpc.add_AvosServiceServicer_to_server(self.servicer, self.server)

        listen_addr = f'[::]:{self.port}'
        self.server.add_insecure_port(listen_addr)
        logger.info(f"AVOS gRPC server starting on {listen_addr}")

        await self.server.start()
        # Wire real-time threat broadcast
        self.orchestrator.alert_callbacks.append(self.servicer.broadcast_threat)

        await self.server.wait_for_termination()

    async def stop(self):
        if self.server:
            await self.server.stop(5)
            logger.info("AVOS gRPC server stopped.")
