"""
AVOS AI - Central Security Orchestrator (CSO)
Heart of the platform — orchestrates all security modules via asyncio event bus
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Optional, Callable
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.ipc.pipe_server import PipeServer
from core.ipc.grpc_server import GRPCServer
from core.scanner.signature_engine import SignatureEngine
from core.behavioral.heuristic_engine import HeuristicEngine
from core.ransomware.ransomware_shield import RansomwareShield
from core.ids_ips.ids_engine import IDSEngine
from core.web_security.waf import WAFEngine
from core.memory.memory_guard import MemoryGuard
from core.rootkit.rootkit_detector import RootkitDetector
from core.ai.threat_predictor import ThreatPredictor
from core.edr.forensic_trail import ForensicTrail
from core.edr.dark_web_monitor import DarkWebMonitor
from core.scanner.usb_monitor import USBMonitor
from core.scanner.autorun_guard import AutorunGuard
from core.scanner.downloads_monitor import DownloadsMonitor
from core.ai.update_engine import IntelligenceUpdater
from core.ai.deepfake_scanner import DeepfakeScanner
from core.db.db_manager import DatabaseManager
from core.payment.payment_shield import PaymentShield
from core.api.http_server import AVOSHTTPServer

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('logs/avos_cso.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('AVOS.CSO')


# ─── Enumerations ────────────────────────────────────────────────────────────
class ThreatLevel(Enum):
    CLEAN    = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


class OperationMode(Enum):
    NORMAL    = "normal"
    GAMER     = "gamer"      # Zero-scan during gaming
    DEVELOPER = "developer"  # Raw logs + whitelisting


# ─── Dataclasses ─────────────────────────────────────────────────────────────
@dataclass
class ThreatEvent:
    event_id:   str
    event_type: str          # file, network, memory, ransomware, usb, etc.
    threat_level: ThreatLevel
    score:      float        # 0.0–100.0
    source:     str          # module that raised the event
    path:       Optional[str]
    pid:        Optional[int]
    details:    dict
    timestamp:  float
    remediated: bool = False
    explanation: str = ""


@dataclass
class ModuleStatus:
    name:    str
    enabled: bool
    healthy: bool
    last_event_time: Optional[float]


# ─── CSO ─────────────────────────────────────────────────────────────────────
class CentralSecurityOrchestrator:
    """Main orchestrator — singleton daemon process."""

    VERSION = "1.0.0"

    def __init__(self, config_path: str = "shared/config/avos_config.yaml"):
        self.config_path   = config_path
        self.config        = self._load_config()
        self.mode          = OperationMode.NORMAL
        self.running       = False

        # Core components
        self.db            = DatabaseManager()
        self.event_bus:    asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.alert_callbacks: List[Callable] = []
        self.modules:      Dict[str, ModuleStatus] = {}

        # Security modules
        self.pipe_server   = PipeServer(self._on_driver_event)
        self.grpc_server   = GRPCServer(self)
        self.sig_engine    = SignatureEngine()
        self.heuristic     = HeuristicEngine()
        self.ransomware    = RansomwareShield()
        self.ids           = IDSEngine()
        self.waf           = WAFEngine()
        self.mem_guard     = MemoryGuard()
        self.rootkit       = RootkitDetector()
        self.ai_predictor  = ThreatPredictor()
        self.forensic      = ForensicTrail(self.db)
        self.dark_web      = DarkWebMonitor(self.db)
        self.usb_monitor   = USBMonitor(self._on_usb_event)
        self.autorun_guard = AutorunGuard(self._on_autorun_event)
        self.downloads     = DownloadsMonitor(self)
        self.updater       = IntelligenceUpdater(self.db, self.sig_engine, self.heuristic)
        self.deepfake      = DeepfakeScanner()
        self.payment_shield = PaymentShield(self.db, self.event_bus)
        self.http_server   = AVOSHTTPServer(self)  # Browser-mode REST bridge

        self._register_modules()

    def _load_config(self) -> dict:
        """Load YAML config, fallback to defaults."""
        try:
            import yaml
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f)
            return self._default_config()
        except Exception:
            return self._default_config()

    def _default_config(self) -> dict:
        return {
            'modules': {
                'signature_scan': True,
                'heuristic':      True,
                'ransomware':     True,
                'ids_ips':        True,
                'waf':            True,
                'memory_guard':   True,
                'rootkit':        True,
                'ai_predictor':   True,
                'dark_web':       True,
                'payment_shield': True,
            },
            'thresholds': {
                'heuristic_alert':  60.0,
                'ai_alert':         70.0,
                'ransomware_files_per_10s': 50,
                'ids_brute_force_per_min':  10,
            },
            'quarantine_path': 'quarantine',
            'log_level': 'INFO'
        }

    def _register_modules(self):
        names = [
            'signature_scan', 'heuristic', 'ransomware', 'ids_ips',
            'waf', 'memory_guard', 'rootkit', 'ai_predictor',
            'dark_web', 'payment_shield', 'usb_monitor', 'autorun_guard',
            'deepfake_scan', 'downloads_monitor'
        ]
        for name in names:
            enabled = self.config.get('modules', {}).get(name, True)
            self.modules[name] = ModuleStatus(
                name=name, enabled=enabled, healthy=True, last_event_time=None
            )

    async def _on_driver_event(self, raw_event: dict):
        event_type = raw_event.get('event_type', 'unknown')
        if self.mode == OperationMode.GAMER and event_type in ('file_write', 'file_create'):
            return
        await self.event_bus.put(raw_event)

    async def _on_usb_event(self, drive_letter: str):
        await self.event_bus.put({'event_type': 'usb_insert', 'path': drive_letter, 'pid': None})

    async def _on_autorun_event(self, key: str, value: str):
        await self._raise_threat(ThreatEvent(
            event_id=self._gen_id(), event_type='autorun', threat_level=ThreatLevel.MEDIUM,
            score=65.0, source='autorun_guard', path=value, pid=None,
            details={'key': key}, timestamp=time.time(), explanation=f"New startup: {value}"
        ))

    async def publish(self, topic: str, data: dict):
        if topic == 'file.scan':
            await self.event_bus.put({'event_type': 'file_create', 'path': data['path'], 'pid': None, 'source': data.get('source')})

    async def process_events(self):
        while self.running:
            try:
                event = await asyncio.wait_for(self.event_bus.get(), timeout=1.0)
                await self._dispatch_event(event)
            except asyncio.TimeoutError: continue
            except Exception as e: logger.error(f"Event error: {e}")

    async def _dispatch_event(self, event: dict):
        etype = event.get('event_type', '')
        path, pid = event.get('path'), event.get('pid')
        if etype in ('file_create', 'file_write', 'file_execute', 'usb_insert'):
            await self._handle_file_event(etype, path, pid)
        elif etype in ('net_connect', 'net_block'): await self._handle_network_event(event)
        elif etype == 'payment_threat': await self._handle_payment_event(event)
        elif etype == 'memory_alert': await self._handle_memory_event(event)

    async def _handle_file_event(self, etype: str, path: Optional[str], pid: Optional[int]):
        if not path or not os.path.exists(path): return
        if self.modules['signature_scan'].enabled:
            res = await asyncio.to_thread(self.sig_engine.scan, path)
            if res.is_threat:
                await self._raise_threat(ThreatEvent(
                    self._gen_id(), 'file_threat', ThreatLevel.CRITICAL, 100.0, 'signature_engine',
                    path, pid, {'hash': res.hash}, time.time(), explanation=f"Malware: {res.signature_name}"
                ))
                return
        if self.modules['heuristic'].enabled:
            res = await asyncio.to_thread(self.heuristic.analyze, path)
            if res.score >= self.config['thresholds']['heuristic_alert']:
                await self._raise_threat(ThreatEvent(
                    self._gen_id(), 'file_suspicious', ThreatLevel.HIGH if res.score >= 80 else ThreatLevel.MEDIUM,
                    res.score, 'heuristic_engine', path, pid, {}, time.time(), explanation=res.explanation
                ))

    async def _handle_network_event(self, event: dict):
        if self.modules['ids_ips'].enabled:
            res = await asyncio.to_thread(self.ids.analyze, event.get('remote_addr'), event.get('remote_port'), event.get('pid'))
            if res.is_threat:
                await self._raise_threat(ThreatEvent(
                    self._gen_id(), 'network_threat', ThreatLevel.HIGH, res.score, 'ids_engine',
                    None, event.get('pid'), res.details, time.time(), explanation=res.explanation
                ))

    async def _handle_payment_event(self, event: dict):
        await self._raise_threat(ThreatEvent(
            self._gen_id(), 'payment_threat', ThreatLevel.CRITICAL, 100.0, 'payment_shield',
            None, event.get('pid'), event, time.time(), explanation="Financial data interception blocked"
        ))

    async def _handle_memory_event(self, event: dict):
        await self._raise_threat(ThreatEvent(
            self._gen_id(), 'memory_threat', ThreatLevel.CRITICAL, 95.0, 'memory_guard',
            None, event.get('pid'), event, time.time(), explanation=f"Memory injection in PID {event.get('pid')}"
        ))

    async def _raise_threat(self, threat: ThreatEvent):
        logger.warning(f"[{threat.threat_level.name}] {threat.event_type} | {threat.path}")
        self.forensic.record_event(threat)
        await asyncio.to_thread(self.db.insert_threat, asdict(threat))
        if threat.threat_level == ThreatLevel.CRITICAL and threat.path:
            await self._quarantine(threat.path)
            threat.remediated = True
        for cb in self.alert_callbacks:
            try: await cb(threat)
            except Exception as e: logger.error(f"Callback error: {e}")

    async def _quarantine(self, path: str):
        try:
            import shutil
            q_path = Path(self.config.get('quarantine_path', 'quarantine'))
            q_path.mkdir(parents=True, exist_ok=True)
            shutil.move(path, str(q_path / Path(path).name))
        except Exception as e: logger.error(f"Quarantine error: {e}")

    def set_mode(self, mode: str):
        try: self.mode = OperationMode(mode); logger.info(f"Mode set to: {self.mode.value}")
        except: logger.error(f"Unknown mode: {mode}")

    def get_status(self) -> dict:
        return {
            'version': self.VERSION, 'mode': self.mode.value, 'running': self.running,
            'modules': {k: asdict(v) for k, v in self.modules.items()}
        }

    async def start(self):
        self.running = True
        await asyncio.to_thread(self.db.initialize)
        # Start the HTTP REST bridge (browser-mode API) in a background thread
        self.http_server.start()
        tasks = [
            asyncio.create_task(self.pipe_server.start()),
            asyncio.create_task(self.grpc_server.start()),
            asyncio.create_task(self.process_events()),
            asyncio.create_task(self.ransomware.start_monitor(self.event_bus)),
            asyncio.create_task(self.mem_guard.start_monitor(self.event_bus)),
            asyncio.create_task(self.rootkit.start_monitor(self.event_bus)),
            asyncio.create_task(self.dark_web.start_monitor()),
            asyncio.create_task(self.usb_monitor.start()),
            asyncio.create_task(self.autorun_guard.start()),
            asyncio.create_task(self.downloads.start()),
            asyncio.create_task(self.updater.run_periodic_update()),
            asyncio.create_task(self.payment_shield.start_monitor(self.event_bus)),
        ]
        logger.info("AVOS ACTIVE — gRPC :50051 · HTTP :8765")
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self):
        self.running = False
        await self.payment_shield.stop()

    @staticmethod
    def _gen_id() -> str:
        import uuid
        return str(uuid.uuid4())[:8]

async def main():
    cso = CentralSecurityOrchestrator()
    signal.signal(signal.SIGINT, lambda s, f: asyncio.create_task(cso.stop()))
    await cso.start()

if __name__ == '__main__':
    asyncio.run(main())
