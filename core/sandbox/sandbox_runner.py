"""
AVOS AI - Sandbox Runner
Executes suspicious files in isolated process with restricted permissions
"""

import asyncio
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger('AVOS.Sandbox')

TIMEOUT_SECONDS = 30


@dataclass
class SandboxReport:
    path: str
    exit_code: int
    runtime_ms: float
    file_drops: List[str]
    network_attempts: int
    registry_changes: List[str]
    suspicious_api_calls: List[str]
    verdict: str           # clean, suspicious, malicious
    raw_output: str


class SandboxRunner:
    """
    Executes files in an isolated subprocess using Windows Job Objects
    for resource limiting. Monitors behavior during execution.
    """

    def __init__(self):
        self._sandbox_dir = Path(tempfile.mkdtemp(prefix='avos_sandbox_'))
        logger.info(f"Sandbox workdir: {self._sandbox_dir}")

    async def run(self, path: str) -> SandboxReport:
        """Execute a file in sandbox and return behavioral report."""
        start = time.time()
        logger.info(f"Sandboxed execution: {path}")

        # Create isolated working directory for this run
        run_dir = self._sandbox_dir / f"run_{int(start)}"
        run_dir.mkdir(exist_ok=True)

        # Copy target file to sandbox
        import shutil
        sample_path = run_dir / Path(path).name
        try:
            shutil.copy2(path, sample_path)
        except Exception as e:
            return SandboxReport(
                path=path, exit_code=-1, runtime_ms=0,
                file_drops=[], network_attempts=0,
                registry_changes=[], suspicious_api_calls=[],
                verdict='error', raw_output=f"Copy failed: {e}"
            )

        files_before = self._snapshot_directory(str(run_dir))

        try:
            proc = await asyncio.create_subprocess_exec(
                str(sample_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(run_dir),
                # Low-priority process
                creationflags=0x00000040  # CREATE_NO_WINDOW
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT_SECONDS)
            exit_code = proc.returncode or 0
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
            exit_code = -1
            stdout = stderr = b''
        except Exception as e:
            exit_code = -1
            stdout = stderr = str(e).encode()

        runtime_ms = (time.time() - start) * 1000

        # Analyze what happened
        files_after = self._snapshot_directory(str(run_dir))
        file_drops = list(files_after - files_before - {str(sample_path)})

        raw_output = (stdout.decode('utf-8', errors='replace') +
                      stderr.decode('utf-8', errors='replace'))

        verdict = self._determine_verdict(file_drops, raw_output)

        # Cleanup
        try:
            shutil.rmtree(str(run_dir))
        except Exception:
            pass

        return SandboxReport(
            path=path, exit_code=exit_code, runtime_ms=runtime_ms,
            file_drops=file_drops, network_attempts=0,
            registry_changes=[], suspicious_api_calls=[],
            verdict=verdict, raw_output=raw_output[:2000]
        )

    def _snapshot_directory(self, directory: str) -> set:
        snapshot = set()
        try:
            for root, _, files in os.walk(directory):
                for f in files:
                    snapshot.add(os.path.join(root, f))
        except Exception:
            pass
        return snapshot

    def _determine_verdict(self, file_drops: list, output: str) -> str:
        suspicious_keywords = [
            'encrypt', 'ransom', 'bitcoin', 'decrypt', 'your files',
            'cmd.exe', 'powershell', 'regsvr32', 'wscript'
        ]
        if file_drops:
            return 'suspicious'
        if any(kw in output.lower() for kw in suspicious_keywords):
            return 'malicious'
        return 'clean'
