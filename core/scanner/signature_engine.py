"""
AVOS AI - Signature-Based Detection Engine
Hash (MD5/SHA256) + YARA rule matching
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger('AVOS.Scanner.Signature')


@dataclass
class ScanResult:
    path: str
    is_threat: bool
    signature_name: str = ""
    hash: str = ""
    scan_type: str = ""  # 'hash' or 'yara'
    severity: str = "UNKNOWN"


class SignatureEngine:
    """Fast signature-based malware detection using hash DB + YARA rules."""

    def __init__(self, db_manager=None):
        self._db = db_manager
        self._yara = None
        self._yara_rules_path = Path("signatures/rules.yar")
        self._load_yara()

    def _load_yara(self):
        try:
            import yara
            if self._yara_rules_path.exists():
                self._yara = yara.compile(str(self._yara_rules_path))
                logger.info(f"YARA rules loaded from {self._yara_rules_path}")
            else:
                # Compile built-in rules
                self._yara = yara.compile(source=BUILTIN_YARA_RULES)
                logger.info("Built-in YARA rules loaded.")
        except ImportError:
            logger.warning("yara-python not installed — YARA scanning disabled.")
            self._yara = None
        except Exception as e:
            logger.error(f"YARA load error: {e}")
            self._yara = None

    def scan(self, path: str) -> ScanResult:
        """Scan a file by hash first, then YARA rules."""
        if not os.path.isfile(path):
            return ScanResult(path=path, is_threat=False)

        # Compute hashes
        md5hash, sha256hash = self._compute_hashes(path)
        if not sha256hash:
            return ScanResult(path=path, is_threat=False)

        # 1. Hash lookup against signature DB
        if self._db:
            sig_name = self._db.get_signature(sha256hash)
            if sig_name:
                logger.warning(f"Hash match: {path} → {sig_name}")
                return ScanResult(
                    path=path, is_threat=True,
                    signature_name=sig_name, hash=sha256hash,
                    scan_type='hash', severity='CRITICAL'
                )

        # 2. YARA scan
        if self._yara:
            try:
                matches = self._yara.match(path)
                if matches:
                    rule_names = [m.rule for m in matches]
                    logger.warning(f"YARA match: {path} → {rule_names}")
                    return ScanResult(
                        path=path, is_threat=True,
                        signature_name=', '.join(rule_names), hash=sha256hash,
                        scan_type='yara', severity='HIGH'
                    )
            except Exception as e:
                logger.debug(f"YARA scan error on {path}: {e}")

        return ScanResult(path=path, is_threat=False, hash=sha256hash)

    def _compute_hashes(self, path: str):
        """Returns (md5, sha256) tuple."""
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception as e:
            logger.error(f"Hash computation failed for {path}: {e}")
            return None, None

    def add_signature(self, sha256: str, md5: str, name: str, severity: str = 'HIGH'):
        if self._db:
            self._db.add_signature(sha256, md5, name, severity)
            logger.info(f"Signature added: {name} ({sha256[:16]}...)")

    def reload_yara(self):
        self._load_yara()


# ─── Built-in YARA Rules ─────────────────────────────────────────────────────
BUILTIN_YARA_RULES = r"""
rule SuspiciousPEImports {
    meta:
        description = "PE file with suspicious API imports suggesting malware"
        severity = "MEDIUM"
    strings:
        $virt    = "VirtualAlloc" ascii wide
        $wpm     = "WriteProcessMemory" ascii wide
        $crt     = "CreateRemoteThread" ascii wide
        $sfc     = "SfcTerminateWatcherThread" ascii wide
        $keylog  = "SetWindowsHookEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PackedExecutable {
    meta:
        description = "High entropy PE section - likely packed/encrypted"
        severity = "MEDIUM"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mz   = { 4D 5A }
    condition:
        $mz at 0 and any of ($upx*)
}

rule RansomwareExtensionPattern {
    meta:
        description = "File contains ransomware-like extension targeting strings"
        severity = "HIGH"
    strings:
        $enc1 = ".encrypted" ascii
        $enc2 = ".locked"    ascii
        $enc3 = ".WNCRY"     ascii
        $enc4 = ".CERBER"    ascii
        $note = "HOW_TO_DECRYPT" ascii
        $note2 = "YOUR_FILES_ARE_ENCRYPTED" ascii
    condition:
        any of them
}

rule SuspiciousPowerShell {
    meta:
        description = "PowerShell dropper patterns"
        severity = "HIGH"
    strings:
        $dl  = "DownloadString" ascii wide
        $iex = "IEX(" ascii wide
        $b64 = "FromBase64String" ascii wide
        $enc = "-EncodedCommand" ascii wide
        $byp = "bypass" ascii wide nocase
    condition:
        3 of them
}

rule MimikatzPattern {
    meta:
        description = "Mimikatz credential dumper patterns"
        severity = "CRITICAL"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "lsadump::sam" ascii wide nocase
        $m3 = "mimikatz" ascii wide nocase
        $m4 = "privilege::debug" ascii wide nocase
    condition:
        any of them
}

rule ShellcodePattern {
    meta:
        description = "Common shellcode NOP sled patterns"
        severity = "HIGH"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
        $sc1 = { EB 04 ?? ?? FF E4 }
        $sc2 = { 64 A1 30 00 00 00 }   // PEB access
    condition:
        any of them
}
"""
