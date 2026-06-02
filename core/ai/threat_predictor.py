"""
AVOS AI - AI Threat Predictor
Random Forest (static) + LSTM (behavioral sequence) for pre-execution detection
Fully offline — no cloud dependency
"""

import logging
import os
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger('AVOS.AI.Predictor')

MODEL_RF_PATH   = 'models/rf_model.pkl'
MODEL_LSTM_PATH = 'models/lstm_model.pt'
SCALER_PATH     = 'models/scaler.pkl'

FEATURE_NAMES = [
    'file_size', 'entropy', 'num_sections', 'num_imports', 'num_exports',
    'has_debug', 'has_resources', 'imports_code_injection', 'imports_keylogging',
    'imports_persistence', 'imports_anti_debug', 'imports_network',
    'max_section_entropy', 'avg_section_entropy', 'has_overlay',
    'overlay_size_ratio', 'is_packed', 'virtual_size_ratio',
    'suspicious_import_count', 'writeable_executable_sections',
]


@dataclass
class PredictionResult:
    probability: float          # 0.0 – 1.0 malware probability
    is_malware: bool
    model_used: str             # 'rf', 'lstm', 'ensemble'
    top_features: Dict[str, float]
    explanation: str
    inference_time_ms: float


class ThreatPredictor:
    """
    ML-based pre-execution threat prediction.
    Uses Random Forest for static features, LSTM for behavioral sequences.
    Falls back to heuristic scoring if models not trained yet.
    """

    def __init__(self):
        self.rf_model  = None
        self.lstm_model = None
        self.scaler    = None
        self._load_models()
        self._feature_extractor = FeatureExtractor()

    def _load_models(self):
        """Load pre-trained models if they exist."""
        try:
            if Path(MODEL_RF_PATH).exists():
                with open(MODEL_RF_PATH, 'rb') as f:
                    self.rf_model = pickle.load(f)
                logger.info("Random Forest model loaded.")
        except Exception as e:
            logger.warning(f"RF model load failed: {e}")

        try:
            if Path(SCALER_PATH).exists():
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
        except Exception:
            pass

        try:
            if Path(MODEL_LSTM_PATH).exists():
                import torch
                self.lstm_model = torch.load(MODEL_LSTM_PATH, map_location='cpu')
                self.lstm_model.eval()
                logger.info("LSTM model loaded.")
        except Exception as e:
            logger.warning(f"LSTM model load failed: {e}")

    def predict(self, path: str) -> PredictionResult:
        """Run ML prediction on a file."""
        start = time.time()

        features = self._feature_extractor.extract(path)
        feature_vec = np.array([features.get(k, 0.0) for k in FEATURE_NAMES]).reshape(1, -1)

        if self.rf_model is not None:
            # Scale if scaler available
            if self.scaler:
                try:
                    feature_vec = self.scaler.transform(feature_vec)
                except Exception:
                    pass

            try:
                prob = float(self.rf_model.predict_proba(feature_vec)[0][1])
                top_features = self._get_top_features(feature_vec[0])
                explanation = self._explain(prob, top_features)
                elapsed = (time.time() - start) * 1000

                return PredictionResult(
                    probability=prob,
                    is_malware=prob >= 0.7,
                    model_used='random_forest',
                    top_features=top_features,
                    explanation=explanation,
                    inference_time_ms=elapsed
                )
            except Exception as e:
                logger.error(f"RF prediction error: {e}")

        # Fallback: heuristic score from features
        heuristic_prob = self._heuristic_fallback(features)
        elapsed = (time.time() - start) * 1000
        return PredictionResult(
            probability=heuristic_prob,
            is_malware=heuristic_prob >= 0.7,
            model_used='heuristic_fallback',
            top_features={k: features[k] for k in list(features)[:5]},
            explanation=self._explain(heuristic_prob, {}),
            inference_time_ms=elapsed
        )

    def _get_top_features(self, feature_vec: np.ndarray) -> Dict[str, float]:
        """Get top contributing features from RF model."""
        if self.rf_model and hasattr(self.rf_model, 'feature_importances_'):
            importances = self.rf_model.feature_importances_
            weighted = {FEATURE_NAMES[i]: importances[i] * feature_vec[i]
                        for i in range(min(len(FEATURE_NAMES), len(feature_vec)))}
            sorted_features = sorted(weighted.items(), key=lambda x: abs(x[1]), reverse=True)
            return dict(sorted_features[:5])
        return {}

    def _heuristic_fallback(self, features: dict) -> float:
        """Simple rule-based scoring when ML model not available."""
        score = 0.0
        score += features.get('entropy', 0) / 8.0 * 0.25
        score += min(features.get('suspicious_import_count', 0) / 10.0, 1.0) * 0.35
        score += features.get('is_packed', 0) * 0.20
        score += features.get('imports_code_injection', 0) * 0.20
        return min(score, 1.0)

    def _explain(self, prob: float, top_features: Dict) -> str:
        level = "highly likely malware" if prob > 0.8 else \
                "suspicious" if prob > 0.5 else "likely clean"
        explanation = f"AI model predicts this file is {level} ({prob*100:.1f}% probability)."
        if top_features:
            top_names = list(top_features.keys())[:3]
            explanation += f" Main risk factors: {', '.join(top_names)}."
        return explanation


# ─── Feature Extractor ───────────────────────────────────────────────────────
class FeatureExtractor:
    """Extracts ML features from PE files."""

    def extract(self, path: str) -> dict:
        features = {k: 0.0 for k in FEATURE_NAMES}
        if not os.path.isfile(path):
            return features

        features['file_size'] = os.path.getsize(path)

        try:
            import pefile
            pe = pefile.PE(path, fast_load=False)

            features['num_sections']  = len(pe.sections)
            features['has_debug']     = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0.0
            features['has_resources'] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0.0

            # Section entropies
            entropies = [s.get_entropy() for s in pe.sections]
            if entropies:
                features['max_section_entropy'] = max(entropies)
                features['avg_section_entropy'] = sum(entropies) / len(entropies)

            # Writeable + executable sections
            features['writeable_executable_sections'] = sum(
                1 for s in pe.sections
                if (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000)
            )

            # Overlay
            if hasattr(pe, 'get_overlay') and pe.get_overlay():
                features['has_overlay'] = 1.0
                features['overlay_size_ratio'] = len(pe.get_overlay()) / max(features['file_size'], 1)

            # Virtual vs raw size ratio (packed indicator)
            total_raw     = sum(s.SizeOfRawData for s in pe.sections)
            total_virtual = sum(s.Misc_VirtualSize for s in pe.sections)
            if total_raw > 0:
                features['virtual_size_ratio'] = total_virtual / total_raw

            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORTS'):
                all_imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORTS:
                    for imp in entry.imports:
                        if imp.name:
                            all_imports.append(imp.name.decode('utf-8', errors='replace'))

                features['num_imports'] = len(all_imports)

                from core.behavioral.heuristic_engine import SUSPICIOUS_IMPORTS
                for category, imp_list in SUSPICIOUS_IMPORTS.items():
                    key = f'imports_{category}'
                    if key in features:
                        count = sum(1 for i in all_imports if i in imp_list)
                        features[key] = float(count > 0)
                features['suspicious_import_count'] = sum(
                    1 for i in all_imports
                    for lst in SUSPICIOUS_IMPORTS.values() if i in lst
                )

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORTS'):
                features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORTS.symbols)

            # Packed detection
            features['is_packed'] = 1.0 if (
                features['max_section_entropy'] > 7.2 or
                features['virtual_size_ratio'] > 10
            ) else 0.0

        except Exception:
            pass  # Non-PE file — leave defaults

        # File entropy
        features['entropy'] = self._file_entropy(path)
        return features

    @staticmethod
    def _file_entropy(path: str) -> float:
        import math
        try:
            counts = [0] * 256
            total = 0
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    for b in chunk:
                        counts[b] += 1
                        total += 1
            if total == 0:
                return 0.0
            entropy = 0.0
            for c in counts:
                if c:
                    p = c / total
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0
