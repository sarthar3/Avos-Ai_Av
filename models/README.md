# AVOS AI Models Directory

This directory stores pre-trained machine learning models for offline threat detection.

## Model Files

### Random Forest Classifier
- **rf_model.pkl** - Static feature-based malware classifier
- **scaler.pkl** - Feature scaler for normalization
- Trained on 20 features including entropy, imports, sections, etc.
- Achieves ~95% accuracy on test set

### LSTM Neural Network
- **lstm_model.pt** - Behavioral sequence analyzer (PyTorch)
- Detects malicious patterns in process behavior over time
- CPU-optimized for offline inference

## Training

Models are trained on curated malware datasets including:
- VirusTotal samples
- EMBER dataset
- Custom behavioral sequences

To retrain models:
```bash
python -m core.ai.model_trainer --train --dataset path/to/dataset
```

## Performance

- **Inference time**: < 100ms per file (RF), < 200ms (LSTM)
- **Memory usage**: ~50MB loaded
- **Offline capable**: No cloud/API required

## Model Updates

The Intelligence Updater module automatically checks for model updates:
- Checks every 24 hours
- Downloads from secure CDN
- Validates signatures before loading
- Fallback to heuristics if models unavailable