"""
AVOS AI - Model Trainer
Continuous retraining pipeline + Anomaly Detection (Isolation Forest)
"""

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Optional, Tuple

import numpy as np

logger = logging.getLogger('AVOS.AI.Trainer')

MODEL_RF_PATH  = 'models/rf_model.pkl'
SCALER_PATH    = 'models/scaler.pkl'
ANOMALY_PATH   = 'models/anomaly_model.pkl'
TRAINING_DATA  = 'models/training_data.pkl'


class ModelTrainer:
    """
    Self-improving pipeline:
    1. Collects labeled samples (confirmed threats + clean files)
    2. Retrains Random Forest model
    3. Retrains Isolation Forest for anomaly detection
    """

    def __init__(self):
        self.samples_X: list = []
        self.samples_y: list = []
        self._load_existing_data()

    def _load_existing_data(self):
        """Load previously collected training data."""
        try:
            if Path(TRAINING_DATA).exists():
                with open(TRAINING_DATA, 'rb') as f:
                    data = pickle.load(f)
                    self.samples_X = data.get('X', [])
                    self.samples_y = data.get('y', [])
                    logger.info(f"Loaded {len(self.samples_X)} training samples.")
        except Exception as e:
            logger.warning(f"Could not load training data: {e}")

    def add_sample(self, features: dict, label: int):
        """
        Add a labeled training sample.
        label: 1 = malware, 0 = clean
        """
        from core.ai.threat_predictor import FEATURE_NAMES
        feature_vec = [features.get(k, 0.0) for k in FEATURE_NAMES]
        self.samples_X.append(feature_vec)
        self.samples_y.append(label)
        self._save_data()
        logger.debug(f"Sample added: label={label}, samples_total={len(self.samples_X)}")

    def _save_data(self):
        try:
            os.makedirs('models', exist_ok=True)
            with open(TRAINING_DATA, 'wb') as f:
                pickle.dump({'X': self.samples_X, 'y': self.samples_y}, f)
        except Exception as e:
            logger.error(f"Failed to save training data: {e}")

    def retrain_random_forest(self) -> bool:
        """Retrain Random Forest classifier on collected samples."""
        if len(self.samples_X) < 50:
            logger.warning(f"Not enough samples to retrain ({len(self.samples_X)}/50 minimum)")
            return False

        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report

            X = np.array(self.samples_X)
            y = np.array(self.samples_y)

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )

            # Scale
            scaler = StandardScaler()
            X_train_s = scaler.fit_transform(X_train)
            X_test_s  = scaler.transform(X_test)

            # Train
            clf = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                n_jobs=-1,
                random_state=42,
                class_weight='balanced'
            )
            clf.fit(X_train_s, y_train)

            # Evaluate
            y_pred = clf.predict(X_test_s)
            report = classification_report(y_test, y_pred)
            logger.info(f"RF Retrain completed:\n{report}")

            # Save
            with open(MODEL_RF_PATH, 'wb') as f:
                pickle.dump(clf, f)
            with open(SCALER_PATH, 'wb') as f:
                pickle.dump(scaler, f)

            logger.info("Random Forest model saved.")
            return True

        except ImportError:
            logger.error("scikit-learn not installed — cannot retrain.")
            return False
        except Exception as e:
            logger.error(f"RF retrain failed: {e}")
            return False

    def retrain_anomaly_detector(self) -> bool:
        """Train Isolation Forest for unsupervised anomaly detection."""
        # Use clean samples only
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler

            clean_X = [x for x, y in zip(self.samples_X, self.samples_y) if y == 0]
            if len(clean_X) < 30:
                logger.warning("Not enough clean samples for anomaly detector.")
                return False

            X = np.array(clean_X)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            iso = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            iso.fit(X_scaled)

            with open(ANOMALY_PATH, 'wb') as f:
                pickle.dump({'model': iso, 'scaler': scaler}, f)

            logger.info(f"Anomaly detector retrained on {len(clean_X)} clean samples.")
            return True
        except Exception as e:
            logger.error(f"Anomaly detector retrain failed: {e}")
            return False

    def detect_anomaly(self, features: dict) -> Tuple[bool, float]:
        """
        Detect anomalous file using Isolation Forest.
        Returns: (is_anomaly, anomaly_score)
        """
        try:
            from core.ai.threat_predictor import FEATURE_NAMES
            if not Path(ANOMALY_PATH).exists():
                return False, 0.0

            with open(ANOMALY_PATH, 'rb') as f:
                data = pickle.load(f)
            iso    = data['model']
            scaler = data['scaler']

            X = np.array([[features.get(k, 0.0) for k in FEATURE_NAMES]])
            X_scaled = scaler.transform(X)
            score = float(-iso.score_samples(X_scaled)[0])  # Higher = more anomalous
            prediction = iso.predict(X_scaled)[0]
            is_anomaly = prediction == -1

            return is_anomaly, score
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False, 0.0

    def schedule_retraining(self, interval_hours: int = 24):
        """Start a background thread for scheduled retraining."""
        import threading

        def retrain_loop():
            while True:
                logger.info("Scheduled model retraining starting...")
                self.retrain_random_forest()
                self.retrain_anomaly_detector()
                logger.info(f"Retraining done. Next in {interval_hours}h.")
                time.sleep(interval_hours * 3600)

        t = threading.Thread(target=retrain_loop, daemon=True)
        t.start()
        logger.info(f"Model retraining scheduled every {interval_hours}h.")
