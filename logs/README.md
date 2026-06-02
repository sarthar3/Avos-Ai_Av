# AVOS Logs Directory

This directory stores runtime logs and the SQLite database for the AVOS security platform.

## Contents

- **avos_cso.log** - Main orchestrator log file with all security events and system operations
- **avos.db** - SQLite database containing:
  - Threat events and detections
  - Quarantined file records
  - Malware signatures
  - Breach alerts
  - EDR forensic events
  - Configuration settings
  - Encrypted vault for sensitive keys

## Log Rotation

Logs are automatically rotated when they exceed 10MB. Old logs are archived with timestamps.

## Database Initialization

Initialize the database with:
```bash
python -m core.db.db_manager --init
```

## Security Notes

- The database contains sensitive security information
- Vault table stores encrypted keys (e.g., payment tokenizer keys)
- Regular backups recommended for forensic analysis
- Do not delete logs during active investigations