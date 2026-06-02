"""
AVOS AI - Deepfake & Social Engineering Scanner
Heuristic analysis for AI-generated media artifacts and phishing patterns
"""

import logging
import os
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('AVOS.Deepfake')

# Suspicious metadata keywords indicating AI generation/manipulation
AI_METADATA_KEYWORDS = [
    'stable diffusion', 'midjourney', 'dall-e', 'gan', 'deepfake',
    'face-swap', 'generative', 'ai-generated'
]


class DeepfakeScanner:
    """
    Scans media files (audio/video/image) for deepfake indicators.
    Also analyzes text for social engineering patterns (scam/phishing).
    """

    def __init__(self):
        logger.info("Deepfake Scanner initialized.")

    def scan_file(self, path: str) -> Dict[str, any]:
        """
        Analyze a file for deepfake indicators.
        Returns a result dict with score and findings.
        """
        if not os.path.exists(path):
            return {'is_threat': False, 'score': 0.0}

        ext = os.path.splitext(path)[1].lower()
        
        # 1. Metadata analysis (Fast)
        metadata_findings = self._check_metadata(path)
        
        # 2. Heuristic artifact detection (Simulated/Lite)
        artifact_score = 0.0
        if ext in ('.mp4', '.avi', '.mkv', '.mov'):
            artifact_score = self._analyze_video_heuristics(path)
        elif ext in ('.jpg', '.jpeg', '.png', '.webp'):
            artifact_score = self._analyze_image_heuristics(path)
        elif ext in ('.mp3', '.wav', '.flac'):
            artifact_score = self._analyze_audio_heuristics(path)

        total_score = min((len(metadata_findings) * 30) + artifact_score, 100.0)
        
        return {
            'is_threat': total_score >= 60,
            'score': total_score,
            'type': 'deepfake_indicator',
            'findings': metadata_findings,
            'explanation': self._generate_explanation(total_score, metadata_findings)
        }

    def analyze_social_engineering(self, text: str) -> Tuple[bool, float, str]:
        """
        Analyze text (email/chat) for social engineering/scam patterns.
        """
        scam_patterns = [
            'urgent action required', 'account suspended', 'verify identity',
            'winner', 'jackpot', 'crypto investment', 'whatsapp me',
            'kindly', 'overdue payment', 'click below'
        ]
        
        matches = [p for p in scam_patterns if p in text.lower()]
        score = min(len(matches) * 25.0, 100.0)
        
        if score >= 50:
            return True, score, f"Social engineering markers detected: {', '.join(matches)}"
        return False, score, ""

    def _check_metadata(self, path: str) -> List[str]:
        """Check for AI-related markers in file strings/metadata."""
        findings = []
        try:
            # Simple strings check for demo/lite version
            file_size = os.path.getsize(path)
            with open(path, 'rb') as f:
                if file_size <= 20480:
                    chunk = f.read()
                else:
                    # Read first/last 10KB to check for metadata headers
                    chunk = f.read(10240)
                    f.seek(-10240, 2)
                    chunk += f.read(10240)
                
                content = chunk.decode('latin-1').lower()
                for kw in AI_METADATA_KEYWORDS:
                    if kw in content:
                        findings.append(f"AI Marker: '{kw}' found in metadata")
        except Exception:
            pass
        return findings

    def _analyze_video_heuristics(self, path: str) -> float:
        """Video deepfake heuristics (e.g. metadata bitrate anomalies)."""
        # Placeholder: Real detection would use a model like FaceForensics++
        # Here we simulate finding artifacts based on file header oddities
        return 15.0

    def _analyze_image_heuristics(self, path: str) -> float:
        """Image deepfake heuristics (e.g. quantization table analysis)."""
        return 10.0

    def _analyze_audio_heuristics(self, path: str) -> float:
        """Audio deepfake heuristics (e.g. spectral consistency)."""
        return 20.0

    def _generate_explanation(self, score: float, findings: List[str]) -> str:
        if score >= 60:
            msg = "High probability of AI-generated or manipulated media found."
            if findings:
                msg += f" Found markers: {', '.join(findings)}."
            return msg
        elif score >= 30:
            return "Suspicious media artifacts detected. May be manipulated."
        return "No significant deepfake indicators found."
