"""
AVOS AI - IDS/IPS Engine
Detects DDoS, brute force, port scanning, and blocks via Windows Firewall
"""

import asyncio
import logging
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger('AVOS.IDS')

# Thresholds
DDOS_CONNECTIONS_PER_SECOND = 100
BRUTE_FORCE_FAILURES_PER_MIN = 10
PORT_SCAN_PORTS_PER_5S = 20


@dataclass
class IDSResult:
    is_threat: bool
    score: float
    threat_type: str
    explanation: str
    details: dict


class IDSEngine:
    """Intrusion Detection/Prevention system."""

    def __init__(self):
        # Track connection counts per source IP
        self._connections: defaultdict = defaultdict(lambda: deque())
        # Track auth failures per source IP
        self._auth_failures: defaultdict = defaultdict(lambda: deque())
        # Track port access counts per source IP
        self._port_scans: defaultdict = defaultdict(lambda: defaultdict(int))
        # Already blocked IPs
        self._blocked_ips: set = set()

    def analyze(self, remote_addr: Optional[str], remote_port: Optional[int], pid: Optional[int]) -> IDSResult:
        """Analyze a network connection event."""
        if not remote_addr:
            return IDSResult(False, 0.0, '', '', {})

        now = time.time()
        self._connections[remote_addr].append(now)

        # Trim old entries
        cutoff_1s  = now - 1
        cutoff_60s = now - 60
        cutoff_5s  = now - 5

        while self._connections[remote_addr] and self._connections[remote_addr][0] < cutoff_1s:
            self._connections[remote_addr].popleft()

        # 1. DDoS detection
        conn_count = len(self._connections[remote_addr])
        if conn_count >= DDOS_CONNECTIONS_PER_SECOND:
            if remote_addr not in self._blocked_ips:
                self._block_ip(remote_addr)
            return IDSResult(
                is_threat=True, score=95.0,
                threat_type='ddos',
                explanation=f"DDoS detected from {remote_addr}: {conn_count} connections/second",
                details={'source_ip': remote_addr, 'connections_per_sec': conn_count}
            )

        # 2. Port scan detection
        if remote_port:
            self._port_scans[remote_addr][remote_port] = now
            # Count unique ports in last 5s
            recent_ports = [p for p, t in self._port_scans[remote_addr].items() if now - t < 5]
            if len(recent_ports) >= PORT_SCAN_PORTS_PER_5S:
                if remote_addr not in self._blocked_ips:
                    self._block_ip(remote_addr)
                return IDSResult(
                    is_threat=True, score=80.0,
                    threat_type='port_scan',
                    explanation=f"Port scan from {remote_addr}: {len(recent_ports)} ports in 5s",
                    details={'source_ip': remote_addr, 'unique_ports': recent_ports}
                )

        return IDSResult(is_threat=False, score=0.0, threat_type='', explanation='', details={})

    def record_auth_failure(self, source_ip: str):
        """Record an authentication failure (call from log parser)."""
        now = time.time()
        self._auth_failures[source_ip].append(now)
        cutoff = now - 60
        while self._auth_failures[source_ip] and self._auth_failures[source_ip][0] < cutoff:
            self._auth_failures[source_ip].popleft()

        failure_count = len(self._auth_failures[source_ip])
        if failure_count >= BRUTE_FORCE_FAILURES_PER_MIN:
            if source_ip not in self._blocked_ips:
                logger.warning(f"Brute force from {source_ip}: {failure_count} failures/min")
                self._block_ip(source_ip)

    def _block_ip(self, ip: str):
        """Block IP via Windows Firewall rule."""
        try:
            rule_name = f"AVOS_BLOCK_{ip.replace('.', '_')}"
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=in', 'action=block',
                 f'remoteip={ip}', 'enable=yes'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._blocked_ips.add(ip)
                logger.info(f"Blocked IP via firewall: {ip}")
            else:
                logger.error(f"Firewall block failed for {ip}: {result.stderr}")
        except Exception as e:
            logger.error(f"IP block error: {e}")

    def unblock_ip(self, ip: str):
        """Remove firewall block rule for an IP."""
        try:
            rule_name = f"AVOS_BLOCK_{ip.replace('.', '_')}"
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                capture_output=True, text=True, timeout=10
            )
            self._blocked_ips.discard(ip)
            logger.info(f"Unblocked IP: {ip}")
        except Exception as e:
            logger.error(f"IP unblock error: {e}")

    def get_blocked_ips(self) -> list:
        return list(self._blocked_ips)
