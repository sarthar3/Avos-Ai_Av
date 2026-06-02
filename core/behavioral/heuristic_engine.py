"""
AVOS AI - Behavioral / Heuristic Analysis Engine
PE file feature extraction + rule-based scoring
"""

import logging
import math
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger('AVOS.Behavioral')

# PE suspicious import lists
SUSPICIOUS_IMPORTS = {
    'code_injection': ['VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
                       'CreateRemoteThread', 'NtCreateThreadEx'],
    'process_hollowing': ['ZwUnmapViewOfSection', 'NtUnmapViewOfSection',
                          'SetThreadContext', 'ResumeThread'],
    'credential_theft': ['LsaEnumerateLogonSessions', 'SamQueryInformationUser',
                         'NtlmEncryptMessage'],
    'persistence': ['RegSetValueEx', 'RegCreateKeyEx', 'CreateService',
                    'ChangeServiceConfig'],
    'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                   'NtQueryInformationProcess', 'OutputDebugString'],
    'keylogging': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyboardState'],
    'network': ['WSAStartup', 'connect', 'InternetOpen', 'URLDownloadToFile'],
    'evasion': ['VirtualProtect', 'HeapCreate', 'LoadLibraryA', 'GetProcAddress'],
}

SUSPICIOUS_SECTIONS = ['.upx', '.UPX', 'UPX0', 'UPX1', '.packed', '.enigma']


@dataclass
class HeuristicResult:
    score: float                  # 0.0 – 100.0
    is_suspicious: bool
    details: Dict
    explanation: str
    indicators: List[str] = field(default_factory=list)


class HeuristicEngine:
    """Analyzes PE files for suspicious behavioral patterns."""

    THRESHOLDS = {
        'high_entropy_section': 7.2,
        'alert_score':          60.0,
    }

    def analyze(self, path: str) -> HeuristicResult:
        """Run full heuristic analysis on a file."""
        if not os.path.isfile(path):
            return HeuristicResult(0.0, False, {}, "File not found")

        try:
            import pefile
            pe = pefile.PE(path, fast_load=False)
        except ImportError:
            return self._basic_analysis(path)
        except Exception as e:
            logger.debug(f"PE parse failed for {path}: {e}")
            return self._basic_analysis(path)

        score = 0.0
        indicators = []
        details: Dict = {
            'file_size': os.path.getsize(path),
            'imports': {},
            'sections': [],
            'entropy': 0.0,
            'suspicious_imports_count': 0,
        }

        # ── 1. Import analysis ──────────────────────────────────────────────
        import_score, import_indicators, import_details = self._analyze_imports(pe)
        score += import_score
        indicators.extend(import_indicators)
        details['imports'] = import_details
        details['suspicious_imports_count'] = len(import_indicators)

        # ── 2. Section entropy analysis ─────────────────────────────────────
        section_score, section_indicators, sections_info = self._analyze_sections(pe)
        score += section_score
        indicators.extend(section_indicators)
        details['sections'] = sections_info

        # ── 3. Header anomalies ─────────────────────────────────────────────
        header_score, header_indicators = self._analyze_headers(pe)
        score += header_score
        indicators.extend(header_indicators)

        # ── 4. Overall entropy of file ──────────────────────────────────────
        file_entropy = self._file_entropy(path)
        details['entropy'] = round(file_entropy, 3)
        if file_entropy > 7.5:
            score += 20.0
            indicators.append(f"Very high file entropy ({file_entropy:.2f}) — likely packed/encrypted")

        # ── 5. Overlay data ─────────────────────────────────────────────────
        if hasattr(pe, 'get_overlay') and pe.get_overlay():
            overlay_size = len(pe.get_overlay())
            if overlay_size > 50000:
                score += 10.0
                indicators.append(f"Large PE overlay: {overlay_size} bytes (possible data hiding)")

        score = min(score, 100.0)

        explanation = self._build_explanation(score, indicators)
        logger.debug(f"Heuristic {path}: score={score:.1f}, indicators={len(indicators)}")

        return HeuristicResult(
            score=score,
            is_suspicious=score >= self.THRESHOLDS['alert_score'],
            details=details,
            explanation=explanation,
            indicators=indicators
        )

    def _analyze_imports(self, pe):
        score = 0.0
        indicators = []
        details = {}

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORTS:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                imports = [imp.name.decode('utf-8', errors='replace') if imp.name else '' for imp in entry.imports]
                details[dll_name] = imports

                for category, suspicious_list in SUSPICIOUS_IMPORTS.items():
                    found = [f for f in imports if f in suspicious_list]
                    if found:
                        category_score = len(found) * 8
                        score += category_score
                        indicators.append(f"Suspicious {category} imports: {', '.join(found[:3])}")
        except AttributeError:
            pass  # No imports directory

        return min(score, 50.0), indicators, details

    def _analyze_sections(self, pe):
        score = 0.0
        indicators = []
        sections_info = []

        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            entropy = section.get_entropy()
            vsize = section.Misc_VirtualSize
            rsize = section.SizeOfRawData

            sections_info.append({
                'name': name, 'entropy': round(entropy, 3),
                'virtual_size': vsize, 'raw_size': rsize
            })

            if entropy > self.THRESHOLDS['high_entropy_section']:
                score += 15.0
                indicators.append(f"High entropy section '{name}': {entropy:.2f}")

            if name.lower() in [s.lower() for s in SUSPICIOUS_SECTIONS]:
                score += 20.0
                indicators.append(f"Packer section name detected: '{name}'")

            # Executable section with no imports (shellcode-like)
            if section.Characteristics & 0x20000000 and rsize == 0 and vsize > 1000:
                score += 10.0
                indicators.append(f"Executable section '{name}' has no raw data (shellcode staging)")

        return min(score, 40.0), indicators, sections_info

    def _analyze_headers(self, pe):
        score = 0.0
        indicators = []

        try:
            # Unusual subsystem
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            if subsystem not in (2, 3):  # 2=GUI, 3=console
                score += 5.0
                indicators.append(f"Unusual PE subsystem: {subsystem}")

            # No debug info at all
            if pe.OPTIONAL_HEADER.MajorLinkerVersion == 0:
                score += 5.0
                indicators.append("Linker version 0 — unusual for legitimate software")

            # Very small timestamp
            if pe.FILE_HEADER.TimeDateStamp < 978307200:  # Before 2001
                score += 5.0
                indicators.append("PE timestamp before 2001 — possible timestamp manipulation")

        except Exception:
            pass

        return score, indicators

    def _basic_analysis(self, path: str) -> HeuristicResult:
        """Fallback analysis for non-PE files."""
        entropy = self._file_entropy(path)
        score = 0.0
        indicators = []
        if entropy > 7.5:
            score = 30.0
            indicators.append(f"High file entropy: {entropy:.2f}")
        return HeuristicResult(
            score=score, is_suspicious=score >= 60,
            details={'entropy': entropy, 'file_size': os.path.getsize(path)},
            explanation=f"Basic analysis: entropy={entropy:.2f}",
            indicators=indicators
        )

    @staticmethod
    def _file_entropy(path: str) -> float:
        """Calculate Shannon entropy of file."""
        try:
            byte_counts = [0] * 256
            total = 0
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total += 1
            if total == 0:
                return 0.0
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    @staticmethod
    def _build_explanation(score: float, indicators: List[str]) -> str:
        if score >= 80:
            level = "highly suspicious"
        elif score >= 60:
            level = "moderately suspicious"
        elif score >= 30:
            level = "mildly suspicious"
        else:
            level = "likely clean"
        summary = f"File scored {score:.1f}/100 — {level}."
        if indicators:
            summary += f" Key indicators: {'; '.join(indicators[:3])}."
        return summary
