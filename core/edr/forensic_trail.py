"""
AVOS AI - EDR Forensic Trail + Zero Trust Micro-Segmentation
Full attack timelines and forensic audit logs
"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger('AVOS.EDR')


class ForensicTrail:
    """
    Records all security events into structured timeline.
    Builds attack graphs using process parent-child relationships.
    """

    def __init__(self, db_manager=None):
        self._db = db_manager
        # In-memory timeline: {pid: [events]}
        self._timeline: defaultdict = defaultdict(list)
        # Process ancestry: {pid: parent_pid}
        self._process_tree: Dict[int, int] = {}
        # Network policy (Zero Trust): {pid: allowed_hosts_set}
        self._zt_policy: Dict[int, set] = {}

    def record_event(self, threat: Any):
        """Record a ThreatEvent in the forensic trail."""
        try:
            event_dict = asdict(threat) if hasattr(threat, '__dataclass_fields__') else dict(threat)
        except Exception:
            event_dict = {'raw': str(threat)}

        event_dict['recorded_at'] = time.time()
        pid = event_dict.get('pid') or 0
        self._timeline[pid].append(event_dict)

        # Persist to DB
        if self._db:
            try:
                self._db.insert_event({
                    'event_type': event_dict.get('event_type', 'unknown'),
                    'pid': pid,
                    'path': event_dict.get('path'),
                    'details': event_dict.get('details', {}),
                    'timestamp': event_dict.get('timestamp', time.time())
                })
            except Exception as e:
                logger.error(f"DB event insert error: {e}")

    def register_process(self, pid: int, parent_pid: int, process_name: str, path: str):
        """Track process ancestry for attack chain reconstruction."""
        self._process_tree[pid] = parent_pid
        self._timeline[pid].append({
            'event_type': 'process_start',
            'pid': pid,
            'parent_pid': parent_pid,
            'name': process_name,
            'path': path,
            'timestamp': time.time()
        })

    def get_attack_timeline(self, pid: int, depth: int = 5) -> List[dict]:
        """
        Get the full attack timeline for a process and its ancestors.
        Returns chronologically sorted events.
        """
        all_events = []
        current_pid = pid
        visited = set()

        for _ in range(depth):
            if current_pid in visited:
                break
            visited.add(current_pid)
            all_events.extend(self._timeline.get(current_pid, []))
            parent = self._process_tree.get(current_pid)
            if parent is None or parent == 0:
                break
            current_pid = parent

        # Sort by timestamp
        all_events.sort(key=lambda e: e.get('timestamp', 0))
        return all_events

    def get_full_timeline(self, limit: int = 200) -> List[dict]:
        """Get all recorded events across all processes."""
        all_events = []
        for events in self._timeline.values():
            all_events.extend(events)
        all_events.sort(key=lambda e: e.get('timestamp', 0), reverse=True)
        return all_events[:limit]

    def export_timeline_json(self, path: str):
        """Export the full forensic trail to JSON for analysis."""
        try:
            timeline = self.get_full_timeline(limit=10000)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(timeline, f, indent=2, default=str)
            logger.info(f"Forensic trail exported to {path}")
        except Exception as e:
            logger.error(f"Export failed: {e}")

    # ─── Zero Trust Micro-Segmentation ────────────────────────────────────────
    def set_process_policy(self, pid: int, allowed_hosts: set):
        """Associate allowed network destinations with a process (Zero Trust)."""
        self._zt_policy[pid] = allowed_hosts

    def is_connection_allowed(self, pid: int, remote_host: str) -> bool:
        """Check if a process is allowed to connect to a remote host."""
        if pid not in self._zt_policy:
            return True  # No policy = allow (default)
        return remote_host in self._zt_policy[pid]

    def get_process_stats(self) -> Dict[str, Any]:
        """Summary statistics for the dashboard."""
        return {
            'total_processes_tracked': len(self._timeline),
            'total_events': sum(len(v) for v in self._timeline.values()),
            'zero_trust_policies': len(self._zt_policy),
        }
